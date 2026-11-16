VERDICT: changes_requested

1. **BLOCKING — The profile proposition exceeds the cited Lean theorems.**  
   **Location:** §4.1, [sec-security.tex:86](~/.cache/paper-split-review/astra/bundle/src/sec-security.tex:86).

   **Claim:** “The user alone signs in every profile,” and “No set without the user covers a P0 or P1 charter.”

   **Evidence:** `lean/Profiles.lean:21–25` defines only:
   ```
   | .P0 => soleCharter user
   | .P1 => soleCharter user
   | .P2 => userOrG user guardian ids k
   ```
   The cited theorems quantify over these particular formulas. The paper instead permits P1 under “any access structure” (`sec-setting.tex:63`), including `user AND issuer` and `2-of-3 officers`. The user alone cannot satisfy the former; the latter need not contain a user leaf. Moreover, the formal P0 combination includes a committee half, whereas actual P0 uses the owner’s existing key.

   **Suggested fix:** Restrict the proposition explicitly to the modeled single-user charter family. Separate profile-independent algebra from claims about actual P0 execution and arbitrary P1/P2 charters.

2. **BLOCKING — The blindness statements contradict the disclosed views.**  
   **Location:** §2.2, [sec-setting.tex:21](~/.cache/paper-split-review/astra/bundle/src/sec-setting.tex:21); §5, [sec-blindness.tex:26](~/.cache/paper-split-review/astra/bundle/src/sec-blindness.tex:26).

   **Claim:** No operator outside an enclave learns the tweak; before release a node cannot select, delay, or refuse by address, amount, destination, or chain.

   **Evidence:** The paper’s own view table lists `tw`, `X`, chain, and profile at non-TEE birth (`sec-blindness.tex:12`), and says ECDSA slot IDs identify the account before release (`:16`). The same paragraph asserting blindness describes a transaction-enumeration attack. `DESIGN.md:1010` expressly qualifies C10 by the ECDSA-session leakage and by the inability to enumerate candidate transactions.

   Thus a non-TEE ECDSA node can identify an account before releasing its share. A node with enumerable Schnorr candidates can also identify the transaction.

   **Suggested fix:** State the exceptions in the operative blindness claim, not only elsewhere: restrict tweak secrecy to TEE mode, acknowledge ECDSA account identification, and condition Schnorr ticket hiding on transaction uncertainty and absence of disclosure by named actors.

3. **BLOCKING — The release procedure omits the hold check required by the design.**  
   **Location:** §§3.7–3.8, [sec-construction.tex:141](~/.cache/paper-split-review/astra/bundle/src/sec-construction.tex:141); C7, `sec-security.tex:114`.

   **Claim:** A revoked authorization releases no new generation.

   **Evidence:** The construction checks authorization when opening/admitting, then specifies selection, witnessing, and release without a per-generation revocation check. In contrast, `DESIGN.md:604` requires:
   > “Before each release, a node checks on Midnight that `auth_ref` is not revoked”

   It also specifies the freshness requirement relative to the generation’s OBS reports and a two-block hold window before generation 1.

   An implementation following the paper’s procedure can admit a request, observe a subsequent revocation, and nevertheless release generation 2.

   **Suggested fix:** Insert the per-release check, its finalized-ledger freshness condition, and the initial P2 hold delay into the construction. State the transition when revocation occurs after an earlier release.

4. **BLOCKING — C6 incorrectly constrains Byzantine nodes’ individual outputs.**  
   **Location:** §4.2, [sec-security.tex:113](~/.cache/paper-split-review/astra/bundle/src/sec-security.tex:113).

   **Claim:** “No node releases” without an unrevoked authorization, including in non-TEE mode with fewer than \(t\) corrupt nodes.

   **Evidence:** A corrupt non-TEE node possesses its shares and can emit its own partial without authorization. The supporting argument in `DESIGN.md:1006` establishes something different:
   > “honest nodes check §5.4. A release needs `t` nodes”

   A threshold argument cannot prohibit an individual corrupt node from sending a partial.

   **Suggested fix:** Distinguish honest-node behavior from completed threshold release. State the latter’s assumptions separately, including any board-safety or slot-anchor conditions needed for the intended authorization guarantee.

5. **BLOCKING — Recovery is not unconditional for the supported ECDSA access structures.**  
   **Location:** §4.2, [sec-security.tex:122](~/.cache/paper-split-review/astra/bundle/src/sec-security.tex:122); §3.10, `sec-construction.tex:195`.

   **Claim:** After the recovery delay, “the owner exits (P1 always, P2 unless held).”

   **Evidence:** `DESIGN.md:1015` qualifies ECDSA recovery:
   > “the exit first runs a refill session … with every session party online”

   The paper itself acknowledges that refills need every session party (`sec-limits.tex:9`). Consider a P1 ECDSA `2-of-3` group with two available honest members and one permanently unavailable member. After recovery without usable anchored slots, an admitted signing set exists, but the mandatory refill cannot run. An OR branch similarly does not necessarily remove this dependency.

   **Suggested fix:** State recovery availability conditions explicitly: an available admitted set, plus usable ECDSA slots or availability of every required refill participant. Reserve “unconditional” for exemption from policy checks, not guaranteed ability to spend.

6. **BLOCKING — Removing the Taproot tweak term does not produce a signature for the internal key.**  
   **Location:** §3.3, [sec-construction.tex:56](~/.cache/paper-split-review/astra/bundle/src/sec-construction.tex:56).

   **Claim:** Without \(c g_Q t_{\mathrm{tap}}\), “the signature verifies for \(P\) and not for \(Q\).”

   **Evidence:** The challenge is defined at `sec-construction.tex:48` using \(x(Q)\). After removing the tweak term, the equation is
   \[
   s'G=\sigma R+c_Qg_QP.
   \]
   BIP340 verification under \(P\) instead requires
   \[
   s'G=\sigma R+c_PP,
   \quad c_P=H(x(R)\|x(P)\|m).
   \]
   Generally \(c_P\ne g_Qc_Q\). `KeySplit.lean:55–58` proves an identity for a free scalar \(c\); it does not establish this hash-dependent verification claim.

   I also checked a concrete BIP340 example with secret scalar 3, nonce scalar 11, an empty Taproot tree, and a zero message: the complete signature verifies under \(Q\); the modified signature verifies under neither key.

   **Suggested fix:** Say that omitting the term generally invalidates the output-key signature. Remove the claim about verification under \(P\).

7. **BLOCKING — The introduction upgrades an open ECDSA instantiation to an existing result.**  
   **Location:** §1, [sec-intro.tex:22](~/.cache/paper-split-review/astra/bundle/src/sec-intro.tex:22).

   **Claim:** The functionalities preparing the halves “are instantiated by published threshold ECDSA protocols.”

   **Evidence:** `sec-construction.tex:74` states:
   > “Their instantiation at \(t=n-f\) is open (O1, O2)”

   `DESIGN.md:1232–1233` likewise makes choosing and proving the required instantiations explicit obligations; O19 adds the many-party composition obligation. Published candidate protocols do not establish the required interface and security parameters.

   **Suggested fix:** Replace “are instantiated” with “have published candidate instantiations,” and retain the O1/O2/O19 qualifications.

8. **BLOCKING — The latency estimate omits required slot-binding rounds.**  
   **Location:** §7, [sec-eval.tex:63](~/.cache/paper-split-review/astra/bundle/src/sec-eval.tex:63); estimate macros at `results-split.tex:60–63`.

   **Claim:** The normal path has three peer rounds and latency
   \[
   \max(F_M,C+h)+C+2h,
   \]
   or \(2C+3h\) for board-first authorization.

   **Evidence:** `DESIGN.md:893` explicitly requires:
   > “the batched `release` round and two batched bind rounds”

   These are followed by release/combination; the header-partial exchange occurs earlier. The paper counts the release witness but omits both bind rounds. The older latency table in DESIGN.md has the same inconsistency with its updated witness protocol.

   **Suggested fix:** Recompute latency from the specified dependency sequence. Using the paper’s existing per-round convention adds \(2h\) to the displayed TEE formulas. Include the P2 hold delay where applicable and identify the dependence on O36.

9. **BLOCKING — The CPU totals and derived throughput contradict their components.**  
   **Location:** §7, [sec-eval.tex:52](~/.cache/paper-split-review/astra/bundle/src/sec-eval.tex:52); `results-split.tex:40–47`.

   **Claim:** Total CPU is 2.5–6.3 ms at nine nodes and 3.8–10.5 ms at seventeen nodes.

   **Evidence:** The macros give:
   ```
   Request path:       1.8–2.7 ms / 2.4–3.3 ms
   Slot replenishment: 1.2–3.6 ms / 2.0–7.2 ms
   ```
   Their sums are **3.0–6.3 ms** and **4.4–10.5 ms**. Corresponding peak rates are approximately **333** and **227** requests/s/core, rather than 400 and 260. DESIGN.md repeats the inconsistent totals.

   **Suggested fix:** Correct the totals and derived rates, or explain and quantify the overlap or different optimization assumptions that produce them. This is an accounting inconsistency, not an objection to using estimates.

10. **BLOCKING — The universal envelope key/dealing claims are contradicted by the construction.**  
    **Location:** Abstract, [sec-abstract.tex:4](~/.cache/paper-split-review/astra/bundle/src/sec-abstract.tex:4); §1, `sec-intro.tex:20`; §3.6, `sec-construction.tex:98–104`.

    **Claim:** Every key of the envelope is a threshold-PRF output, and an envelope deals only one secret across all request types.

    **Evidence:** `sec-construction.tex:104` specifies a capsule “under its own random key.” `DESIGN.md:460` is explicit:
    > “The capsule key `ck_v` is 32 random bytes that the initiator picks.”

    For P0, `DESIGN.md:476` additionally retains the underlying line dealings:
    > “Those dealings are line dealing’s own and stay.”

    Thus one outer dealing is not the same as one total dealing for P0, and the capsule keys are not PRF outputs.

    **Suggested fix:** Scope the statement to one outer data-key dealing. Enumerate the header/body keys and contribution secrets derived from the PRF, distinguish independently sampled capsule keys, and describe P0’s retained inner dealings.

What I checked and found sound:

- The key-split identities, weighted reconstruction, and scalar-secrecy propositions match their Lean statements, including well-formedness and the distinction between general existence and the threshold-completion bijection.
- The ECDSA two-subset extraction equations and bound-slot counterexample are correctly stated. The precedence propositions also match the supplied model.
- The witness intersection calculation gives the stated bounds of four and six colluding operators.
- Running `sizes.py` reproduced the reported frame sizes, contribution sizes, and signing-set capacities.
- The supplied sources contain 57 theorem declarations and one completion equivalence. All 58 entries in the supplied axiom report list only the stated standard axioms. I inspected these artifacts; I did not independently rebuild the unavailable imported development.
- The checked related-work attributions concerning [FROST](https://www.rfc-editor.org/rfc/rfc9591.html), [Groth–Shoup’s signing service](https://www.shoup.net/papers/tecdsa.pdf), and [adaptive Schnorr security](https://eprint.iacr.org/2023/445) are consistent with those sources. The paper appropriately leaves O6, O20, O26, and O32 open.

I treated the companion [LD] properties as given and did not count missing measurements against the paper.