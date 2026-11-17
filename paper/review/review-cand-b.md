VERDICT: changes_requested

1. **BLOCKING — The construction omits the not-before guard.**

   **Location:** [sec-construction.tex:84](/home/hoskinson/Projects/mpcexperiments/paper/review/src/sec-construction.tex:84), Step B; header at line 26.

   **Claim:** The owner specifies an authorization window `[nb, exp]`, which the protocol respects.

   **Reason and evidence:** Step A checks only `height ≤ exp`. Step B permits OBS whenever the target-chain state is eligible; its eligibility definition contains no board-height window check. Consequently, an honest committee following the paper can accept, anchor, and release a request before `nb`.

   The omitted guard is explicit in [SCHEME.md:186](/home/hoskinson/Projects/mpcexperiments/design/SCHEME.md:186): “`g = a = 1`, the request is ARMED and the board height is in `[nb, exp]`.” The paper’s functionality also requires that “the clock is inside the window.”

   **Suggested fix:** Restore the attempt-opening conditions from SCHEME §3.6 before the OBS rule, including the initial window guard and the conditions for retries and subsequent generations.

2. **BLOCKING — Step A omits BIP340 checks needed by the address-binding proposition.**

   **Location:** [sec-construction.tex:65](/home/hoskinson/Projects/mpcexperiments/paper/review/src/sec-construction.tex:65), checks 2, 3, and 6; [sec-security.tex:43](/home/hoskinson/Projects/mpcexperiments/paper/review/src/sec-security.tex:43).

   **Claim:** A sealed suite-2 message passing Step A commits to a signature that verifies under the address key, without assuming an honest dealer.

   **Reason and evidence:** Canonical curve-point encoding does not require even \(y\). The listed checks do not require the BIP340 representative for either \(X\) or sealed \(R\). A dealer can choose an even-\(y\) \(X\), an odd-\(y\) \(R=kG\), and \(s=k+cx\). The dealing, share checks, and authorship proof can all pass, while BIP340 rejects the resulting signature because its reconstructed nonce has odd \(y\). [BIP340 verification](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#verification) explicitly enforces this condition.

   [SCHEME.md:155](/home/hoskinson/Projects/mpcexperiments/design/SCHEME.md:155) requires “suite 2 requires prefix `0x02`”; line 158 additionally requires “`R := lift_x` of the 32 bytes (even y by construction; reject if not on the curve).” These checks were lost in the paper. Honest-owner normalization does not establish a proposition about every accepted dealing.

   **Suggested fix:** Restore both suite-2 acceptance rules and specify the x-only encoding of the final signature.

3. **BLOCKING — The two-signature Schnorr proposition drops a necessary hypothesis.**

   **Location:** [sec-impossibility.tex:26](/home/hoskinson/Projects/mpcexperiments/paper/review/src/sec-impossibility.tex:26); repeated at [sec-security.tex:179](/home/hoskinson/Projects/mpcexperiments/paper/review/src/sec-security.tex:179) and [sec-formal.tex:13](/home/hoskinson/Projects/mpcexperiments/paper/review/src/sec-formal.tex:13).

   **Claim:** “Two signatures on one slot do not determine \(x\).”

   **Reason and evidence:** This is false without a condition on the binding factors. For suite 3, if \(\rho_0=\rho_1\) and \(c_0\ne c_1\), then
   \[
   s_0=d_1+\rho_0d_2+c_0x,\qquad
   s_1=d_1+\rho_0d_2+c_1x,
   \]
   so \(x=(s_0-s_1)/(c_0-c_1)\). A random-oracle collision may be unlikely, but the proposition is unconditional.

   [formal/lean/REPORT.md:57](/home/hoskinson/Projects/mpcexperiments/formal/lean/REPORT.md:57) states the actual condition: “If `a1 b2 − a2 b1 ≠ 0`, then for every candidate key `x'` there is exactly one pair `(d', e')` consistent with both signatures.” Here that determinant is \(\sigma_0\sigma_1(\rho_1-\rho_0)\). The report also limits this result to signature scalars, rather than the full public view.

   **Suggested fix:** State that two signature equations leave the key algebraically undetermined **when the nonce-coefficient determinant is nonzero**, and preserve the scalar-only scope. Retain the corresponding determinant qualification wherever three-signature extraction is asserted.

4. **BLOCKING — The impossibility theorem does not establish unavoidable key exposure.**

   **Location:** [sec-limits.tex:3](/home/hoskinson/Projects/mpcexperiments/paper/review/src/sec-limits.tex:3); related exhaustive framing at [sec-intro.tex:18](/home/hoskinson/Projects/mpcexperiments/paper/review/src/sec-intro.tex:18).

   **Claim:** After stating that a threshold coalition obtains the key, the paper says the impossibility theorem “shows that the first is inherent,” and elsewhere says “no third answer exists.”

   **Reason and evidence:** The theorem establishes that copying a qualifying continuation produces both signatures it could produce on two chain states. It does not establish extraction of \(x\), arbitrary-message signing, or an exhaustive classification of delegation constructions.

   [formal/lean/REPORT.md:146](/home/hoskinson/Projects/mpcexperiments/formal/lean/REPORT.md:146) describes the general result as “outputs both signatures from every state from which the protocol signs both.” Its separate key-extraction result is explicitly construction-specific: “For an open ECDSA slot … under one `R` give `x`” (line 150). Multiple signatures alone do not imply key recovery.

   **Suggested fix:** Attribute key exposure to this construction’s dealt secrets. Restrict the impossibility conclusion to preventing repeated use of a copyable continuation under its stated hypotheses; remove the claim that general key exposure follows.

5. **NON-BLOCKING — The pending benchmark refresh must reconcile configuration differences, not only timing values.**

   **Location:** [sec-eval.tex:9](/home/hoskinson/Projects/mpcexperiments/paper/review/src/sec-eval.tex:9), nine-node configuration and CPU-cost table; [results.tex:317](/home/hoskinson/Projects/mpcexperiments/paper/review/src/results.tex:317).

   **Claim:** The evaluation describes the paper’s nine-node protocol, whose quorum is six, while reporting 24/28 post checks and 430/306 requests per second.

   **Reason and evidence:** [BENCHMARKS.md:173](/home/hoskinson/Projects/mpcexperiments/impl/BENCHMARKS.md:173) states that those measurements used “quorums of `n - f = 7`.” Its accounting is “3 quorums + t partials,” which gives 24/28 for quorum seven but 21/25 for quorum six. Line 189 also says: “Message sizes use the 130-byte authorship proof; the corrected 196-byte proof … adds 66 bytes to each.”

   **Suggested fix:** Refresh or explicitly label the quorum and proof configuration alongside the measurements, including the simulation configuration. As requested, I have not counted these pending measurement discrepancies against the verdict.