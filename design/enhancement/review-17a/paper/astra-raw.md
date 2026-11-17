VERDICT: changes_requested

1. **BLOCKING — C11 exceeds the corruption tolerance of its settlement mechanism.**  
   **Location:** §4.2, [sec-security.tex:122](BUNDLE_COPY/paper/src/sec-security.tex:122); §3.7, [sec-construction.tex:145](BUNDLE_COPY/paper/src/sec-construction.tex:145).

   **Claim:** “Two final settlements cannot follow one record state,” against “any” adversary.

   **Reason and evidence:** Settlement integrity relies on quorum signers, not just ledger soundness. The construction argues that “two quorums share an honest node.” That premise fails under the advertised adversary. For board-first authorization, DESIGN.md:590 explicitly says: “The contract holds roots and not nullifiers, so it does not check them.” A corrupt committee can certify a root containing two authorizations with the same nullifier and certify FINAL settlements for both. A sound ledger accepts the committee-certified data according to the specified rules. The pinned host input prevents two conflicting transactions from confirming; it does not prevent two false settlement certificates.

   **Suggested fix:** Separate host-chain double-spend prevention from settlement integrity. Bound the latter by the required honest quorum, including for board-first operation, or add ledger-verifiable checks that enforce nullifier and settlement consistency independently of committee honesty.

2. **BLOCKING — C2 conflicts with the paper’s own committee-key recovery attack.**  
   **Location:** §4.2, [sec-security.tex:113](BUNDLE_COPY/paper/src/sec-security.tex:113); §3.2, [sec-construction.tex:35](BUNDLE_COPY/paper/src/sec-construction.tex:35).

   **Claim:** With \(|C|<q\), no coalition of actors can obtain a birth certificate for an address whose whole key it knows.

   **Reason and evidence:** At \(n=17\), the paper gives \(q=t=12\) and explicitly describes recovery of \(x_f\) with ten corrupt nodes. Its condition is
   \[
   3(t-|C|)\le n-|C|.
   \]
   For \(|C|=10\), three forked histories need six of the seven honest nodes, two per history. After recovering the permanent \(x_f\), the coalition can create another address with legitimately generated actor shards and valid proofs of possession. Honest birth checks pass, yet the coalition knows \(x_f+\mathit{tw}+\sum_a x_a\). Ten corrupt nodes satisfy C2’s stated bound \(10<12\).

   The supporting algebra does not prevent this: `lean/KeySplit.lean:46–49` concludes that knowledge of the address key yields \(x_f\) plus the honest shards. It does not establish that this residual remains unknown after protocol executions.

   **Suggested fix:** State the required secrecy assumption on \(x_f\) throughout the preceding execution. For an unanchored non-TEE deployment, use the board-safe corruption bound; otherwise explicitly condition C2 on the slot-anchor construction and its open proof.

3. **BLOCKING — The offline-holder birth proof does not establish that the holder can derive the certified shard.**  
   **Location:** §3.1, [sec-construction.tex:9](BUNDLE_COPY/paper/src/sec-construction.tex:9), lines 15–17; C1, [sec-security.tex:112](BUNDLE_COPY/paper/src/sec-security.tex:112).

   **Claim:** The offline holder obtains \(x_u=u+H_{\mathrm{st}}(uE_c)\), and birth certification establishes shard points whose logarithms their holders know.

   **Reason and evidence:** The creator proves only knowledge of \(\delta\) satisfying \(X_u-U=\delta G\). DESIGN.md:180 specifies the same proof, while the holder derives its scalar from the encrypted \(E_c\).

   A malicious creator can choose \(e_c\) and an unrelated known \(\delta\), publish \(X_u=U+\delta G\), encrypt \(E_c=e_cG\), and give a valid proof of \(\delta\). Every stated birth check passes. The holder nevertheless derives
   \[
   u+H_{\mathrm{st}}(uE_c)\ne u+\delta,
   \]
   except with negligible probability. Thus certification can make an address fundable without giving its intended holder the specified spending secret. Extracting \(u\) and \(\delta\) from two parties’ proofs does not establish that the holder possesses \(\delta\).

   **Suggested fix:** Bind the certified point to the delivered derivation material, including ciphertext correctness, or require the holder to derive the shard, check its public point, and acknowledge before funding.

4. **BLOCKING — ECDSA precedence in the paper disagrees with the supplied design specification.**  
   **Location:** §3.4, [sec-construction.tex:90](BUNDLE_COPY/paper/src/sec-construction.tex:90); §9.1, [sec-limits.tex:56](BUNDLE_COPY/paper/src/sec-limits.tex:56).

   **Claim:** ECDSA precedence starts only with an authorization in force; an unauthorized namer neither blocks another request nor burns its slots.

   **Reason and evidence:** DESIGN.md §4.1, line 306, instead states: “Honest nodes refuse a later request that names a slot under the precedence of another request, even when the later request’s authorization comes into force first.” DESIGN.md:493 applies that precedence check to “every slot,” and line 393 says that honest nodes refuse a second ECDSA claim on the board. The specification contains neither the paper’s ECDSA exception nor obligation O38.

   These rules produce different outcomes for precisely the unauthorized-slot-naming attack discussed in the paper. The paper correctly acknowledges at `sec-security.tex:78` that its Lean precedence proposition does not cover the new rule, but that acknowledgement does not reconcile the construction with DESIGN.md.

   **Suggested fix:** Synchronize the normative specification, claim table, and open obligations with the intended ECDSA rule. Preserve its open status and specify reservation, loss of precedence, and burning consistently.

5. **BLOCKING — The stated slot-size formula omits serialized overhead.**  
   **Location:** §7, [sec-eval.tex:5](BUNDLE_COPY/paper/src/sec-eval.tex:5).

   **Claim:** “The dealings of one committee slot by its \(t\) dealers are \(2t(33t+32n)\) bytes.”

   **Reason and evidence:** This gives 7,266 bytes at \(n=9,t=7\), and 22,560 bytes at \(n=17,t=12\). BENCH.md:75 explicitly says that slot posts “include dealer context, ephemeral key and proof”; its measured one-slot sizes are **8,351** and **24,612** bytes (lines 79–80).

   The discrepancy also affects reconstruction of the board totals from the stated parts. Four times the formula gives 29,064 and 90,240 bytes, whereas measured four-slot batches occupy **30,317** and **92,580** bytes. The approximately 47/110 KB board totals use these larger measured batches.

   **Suggested fix:** Label the formula as commitment-and-ciphertext payload only, and supply the serialized overhead or the measured batch sizes used in the totals.

6. **BLOCKING — The latency estimate counts acknowledged rounds as single peer hops.**  
   **Location:** §7, [sec-eval.tex:68](BUNDLE_COPY/paper/src/sec-eval.tex:68); numerical values in [results-split.tex:76](BUNDLE_COPY/paper/src/results-split.tex:76).

   **Claim:** With \(h\) defined as “one peer hop,” the TEE path takes \(\max(F_M,C+h)+C+4h\), and board-first takes \(2C+5h\).

   **Reason and evidence:** The release witness and both binding stages require acknowledgements before proceeding. DESIGN.md:912 says that the node “proceeds after … acks”; line 916 specifies the sequential release-witness round, slot-entry acknowledgements, and sealed-version acknowledgements.

   With one-way hop latency \(h\), these three stages require \(6h\), followed by another \(h\) for release. Keeping the paper’s other assumptions, the corresponding formulas are therefore at least
   \[
   \max(F_M,C+h)+C+7h,\qquad 2C+8h.
   \]
   At \(h=50\) ms, the quoted examples become \(F_M+1.35\) s, \(F_M+0.85\) s, 2.40 s, and 1.40 s. Batching reduces message count; it does not remove acknowledgement travel.

   **Suggested fix:** Distinguish one-way delay from round-trip delay and recount the sequential dependencies. If \(h\) was intended as completed-round latency, redefine it and consistently account for the one-way exchanges.

7. **BLOCKING — An OR escrow does not uniquely identify profile P2.**  
   **Location:** §5, Table 4, [sec-blindness.tex:12](BUNDLE_COPY/paper/src/sec-blindness.tex:12).

   **Claim:** An OR gate’s escrow dealing and acknowledgements “mark a P2 address.”

   **Reason and evidence:** §2.4 expressly permits P1 “under any access structure” (`sec-setting.tex:63`), and §3.5 applies escrow to any OR gate. DESIGN.md:263 likewise requires an escrow certificate for any record “whose Γ has an OR gate.” Consequently, observing an escrow does not by itself distinguish P2 from a P1 charter containing an OR branch.

   **Suggested fix:** Describe this observation as revealing an escrow branch. Identify any additional public information required to infer P2 specifically.

What I checked and found sound:

- The stated Lean propositions match the supplied hypotheses and quantifiers, including scalar-only secrecy, the threshold-completion bijection, the restricted profile model, and the abstract cold-start statement.
- The modules contain 57 theorems and one equivalence. All 58 appear in the supplied axiom output with only the three stated standard axioms; no `sorry`, custom axiom declaration, or `native_decide` occurs.
- The principal CPU totals, throughput ranges, serialized envelope totals, measured signing-set capacities, contribution sizes, and checkpoint payload sums reconcile with the supplied evidence, allowing for rounding.
- The paper explicitly retains the major open reductions and distinguishes group-half leakage from recovery of the whole ECDSA key.
- All bundle checksums match and remain unchanged. No git or network access was used.

External related-work attributions and novelty could not be independently verified from this bundle: the cited works are not included. I treated [LD]’s cited properties as given, as requested.