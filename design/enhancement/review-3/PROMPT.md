You are an independent reviewer of a cryptographic protocol design. Review it adversarially, as a cryptographer and protocol engineer who wants to find what is wrong.

The bundle (read every file in full):
- BUNDLE_DIR/DESIGN.md: the design ("split-line dealing": a threshold committee co-signs Schnorr/BIP340, Ed25519 and ECDSA transactions with outside shard holders, behind a blinded envelope on a public board).
- BUNDLE_DIR/DECISIONS.md: the numbered decisions the design implements, with reasons.
- BUNDLE_DIR/vectors/check.py, ed.py, sizes.py: executable test vectors for the key algebra (you may read them; do not run them).
The base protocol the design refers to (SCHEME, "line dealing" §3 and similar) is not included; treat its cited properties as given unless the design uses them inconsistently.

Focus areas, in order:
1. Soundness of the key algebra and of the threshold-PRF keying (decisions 26-41): additive split x = x_f + tw + Σ x_a, Lagrange-weighted group shares, FROST-style binding factors and signer-set fixing, header/variant keys as κ_0·H_c(dd ‖ label), DLEQ checks of PRF partials, batch verification with fallback, optimistic combining.
2. Nonce and slot rules: one committee slot per (generation, input) pair shared across variants, G_max generations, shared slots, actor pool pairs per half, burn rules (when a slot or pair must be burned and never reused), slot reservation and release.
3. The merged state machine (ACK merged with release, OPENED merged with ADMIT and OBS, separate OPENED for collecting requests) and board-first authorization.
4. The blindness claims (what operators, actors and the chain learn) and their stated limits.
5. Honesty of claim status: for every claim in the security section, is the status (proved, sketched, open, with its named proof obligation) accurate given the text? Flag any claim marked proved that is not, any obligation that is missing, and any open item that should block a claim.

Report format (Markdown). For every finding:
- ID (F1, F2, ...)
- Severity: blocking (breaks a security claim or makes the protocol unsafe or unimplementable as written), major (a real gap that needs a fix or an honest status change), minor (clarity, inconsistency without security impact)
- Location: the section number(s) of DESIGN.md or the decision number(s)
- Claim affected: the claim id (C*, B*, Theorem *) or the stated property
- Failure scenario: a concrete sequence of steps (who does what, which values) that produces the failure; for algebra, the equations
- Fix: the smallest change that closes it
Then a short list of things you checked and found sound. Do not pad: no finding without a concrete scenario. Write everything in English.
