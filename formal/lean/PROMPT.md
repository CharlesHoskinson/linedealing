# Lane: Lean 4 proofs of the line-dealing algebra

The design is design/SCHEME.md (line dealing). Read it in full, plus design/FINDINGS-LEDGER.md and experiments/line-dealing/checks.py (a pure-Python reference of the algebra and attacks, 36 passing assertions). Treat SCHEME.md as the specification. Do not edit SCHEME.md or anything outside your own folder. Do not commit or push. Run every build or test through heavy-run, e.g. `heavy-run --mem 16G --name <name> -- <cmd>`; if heavy-run is unavailable in your sandbox, run the command directly with low parallelism. No network installs.

Your folder: formal/lean/ . A Lake project is set up there (lakefile.toml, lean-toolchain v4.35.0, Mathlib by local path, builds offline with 'lake build'). Put modules under LineDealing/ and import them from LineDealing.lean.

Model the group abstractly: a field F = ZMod q with q prime ([Fact q.Prime]), and an additive group G that is a Module F G with a fixed nonzero generator g (so a • g = 0 -> a = 0). Points are elements of G, scalar multiplication is •. Shamir shares are evaluations of polynomials of degree < t (Mathlib Polynomial or Lagrange interpolation over distinct nonzero node ids).

Prove, with no sorry and no new axioms:
1. Lagrange linearity: combining partials s_i = h*w_i + r*mu_i from any t distinct ids gives h*w(0) + r*mu(0).
2. Open ECDSA binding: if R = k•g with k != 0, w(0)•R = g and mu(0)•R = X = x•g then w(0) = k⁻¹ and mu(0) = x*k⁻¹; hence s = h*w(0) + r*mu(0) satisfies the ECDSA verification equation s•R = h•g + r•X.
3. Public partial check soundness: if each released s_i satisfies s_i•R = h•W_i + r•M_i where W_i, M_i are the Feldman evaluations of the committed polynomials, then the interpolated s satisfies s•R = h•g + r•X (no honest-share assumption needed).
4. Sealed binding: Schnorr form (p(0)•g = R + c•X implies (R, p(0)) satisfies the Schnorr verification equation) and ECDSA form (p(0)•R = h•g + r•X).
5. Nonce reuse is fatal: two ECDSA signatures with the same R and r != 0 on h1 != h2 (s1 != s2) determine k = (h1-h2)/(s1-s2) and x = (s1*k - h1)/r. And for two-nonce Schnorr, state and prove that two signatures on one slot do NOT determine x (exhibit the one-parameter family), while three generic ones do.
6. Pad reuse is fatal: if ct_w,i = w_i + p_i and ct_mu,i = mu_i + p_i with the same pad, then from the public differences and one signature an observer computes x (state with h + r != 0). With independent pads the differences are mu_i - w_i + (p'_i - p_i), and state the information-theoretic statement you can prove (e.g. for uniformly random independent pads the ciphertext pair is independent of (w_i, mu_i); a counting/bijection form is fine).
7. Resharing preserves the constant terms (SCHEME section 5): the Lagrange combination of reshared polynomials has constant term equal to the original secret, so the committed constant terms stay g and X in base R.
8. BIP340 even-y: you may abstract parity; prove that negating the nonce (k -> -k, R -> -R) together with s -> -k + c*x keeps s•g = R' + c•X for R' = -R.

Build with lake build. Write REPORT.md in your folder (>= 500 words): each theorem name, its statement in plain words, the SCHEME.md claim it supports, what is abstracted (the group, hashing, random oracle and unforgeability are NOT proved here and say so), and the exact build output. Your final message is a short summary.
