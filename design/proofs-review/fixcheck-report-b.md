VERDICT: changes_requested

1: RESOLVED — PROOFS.md §4.2, lines 301–325: `δ_B` now counts internal `H_b`/`H_dg` evaluations, the two-to-one BIP340 normalization, and identity-nonce aborts. B′ and E(a) inherit the corrected TNS bound.

2: RESOLVED — PROOFS.md §1.1, lines 45–46; §2.3, lines 137–172; lines 224, 369, 389: copies are defined by `(hdr, deal, ct)`, included in `Auth`, and simulated with the original shares and slots. This explicitly narrows the experiment without requiring authorization in A, B′ or D.

3: RESOLVED — PROOFS.md §1.2, line 57; §2.2, lines 123–131; §2.3, line 152: the ciphertext digest is now the labelled random oracle `H_ct`, which justifies its birthday-bound contribution.

4: RESOLVED — PROOFS.md §1.2, line 61; §4.3, lines 356–364: the seed-hash assumption and clamped-key support are explicit, and B′ pays the density factor `κ_3 = (q−1)/2^251`.

5: RESOLVED — PROOFS.md §3.2, lines 204–234: one retry per slot gives a hard `4S + 2Q_w` request budget. The second-rejection probability and up to `2S` hidden closing strings are charged explicitly.

6: RESOLVED — PROOFS.md §6.1, lines 419–443: E(c) now claims dealing identity without extraction. E(c′) requires fresh random nonces and subtracts `4Q_s/(q−1)` for collisions with either nonce sign across both continuations.

**NEW BLOCKING — Corollary A′ omits the invalid-child loss.**  
**Location:** [PROOFS.md §3.4, lines 259–267](/home/hoskinson/Projects/mpcexperiments/design/proofs-review/fixcheck/PROOFS.md:259).

The programming argument reduces every sampled `a` modulo `q` and claims the resulting keys follow BIP32. However, BIP32 rejects `a ≥ q` and identity children and advances the child index. [BIP32 child derivation specification](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#child-key-derivation-ckd-functions).

Line 263 acknowledges these cases but discards them without adding a loss to the concrete bound. Already for one edge, `Pr[a ≥ q] = (2^256−q)/2^256`, approximately `2^−127.65`; the stated `|𝒫|²/2^256` programming-collision term does not cover it.

**Suggested fix:** Abort the reduction on an invalid child and add a justified derivation-failure bound—for `L` non-root paths, a conservative bound is `L·((2^256−q)/2^256 + 1/(q−1))`. Alternatively, explicitly restrict the corollary to the simplified modulo-`q` derivation rather than actual BIP32.