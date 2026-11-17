I read all five files in full and did not run the scripts. The honest-execution signing algebra is largely consistent. I found concrete key-recovery attacks, construction failures, and security claims that exceed the protocol’s actual guarantees.

**F1 — Forked board histories allow recovery of the committee root key**

- **Severity:** blocking
- **Location:** §§4.1–4.2, 5.4–5.6, 9.1; decisions 27, 35, 41
- **Claim affected:** C5, C12; obligations O6 and O27
- **Failure scenario:** At launch, corrupt six nodes: fewer than `t = 7`, but enough to manufacture `q = 6` board certificates. The adversary also controls the outside actors, as C5 permits. It presents three conflicting board histories to the three honest nodes. Each history reserves the same committee slot `ℓ` for a different, otherwise valid and authorized request. Each honest node signs exactly once.

  Combining each honest response with the six corrupt responses yields three committee signatures:
  \[
  s_f^{(b)}=\sigma_b(d_\ell+\rho_b e_\ell)+\widetilde c_b x_f.
  \]
  Therefore:
  \[
  \sigma_b s_f^{(b)}
  =d_\ell+\rho_b e_\ell+\sigma_b\widetilde c_b x_f.
  \]
  Three requests with linearly independent coefficient rows reveal `d_ℓ`, `e_ℓ`, and the permanent `x_f`. No honest node reused its nonce.

  The assertion that all honest nodes see one anchor requires board safety at `|C| ≤ f`; it does not follow from `|C| < t`.
- **Fix:** Either restrict the claims to the board’s actual Byzantine bound, or require every honest signer to check a unique, finalized `slot → ticket` assignment on an independently secure ledger. O6 must cover the implemented adversary, rather than assume a one-query oracle that this protocol fails to enforce.

**F2 — ECDSA slots shared across signing subsets permit key recovery**

- **Severity:** blocking
- **Location:** §§3.6 step 7, 4.4, 5.9, 9.1; decisions 22, 24, 27
- **Claim affected:** C4, C17, C18; the sealed guarantee for threshold groups
- **Failure scenario:** Use a charter with a 2-of-3 actor group `{A,B,C}`. Corrupt the committee and actor `A`; this actor coalition is outside the access structure.

  The initiator `A` sends one request with signing set `{A,B}` and hash `h₁`, and another with `{A,C}` and hash `h₂ ≠ h₁`. Both name the same ECDSA slot. Honest `B` and `C` each answer once, so neither violates its local nonce rule. Section 3.6 deliberately makes the slot usable by either subset.

  Interpolation gives two evaluations of the same group half-line:
  \[
  u_1=h_1w_\gamma+r\mu_\gamma,\qquad
  u_2=h_2w_\gamma+r\mu_\gamma.
  \]
  Thus:
  \[
  w_\gamma=(u_1-u_2)/(h_1-h_2),\qquad
  \mu_\gamma=(u_1-h_1w_\gamma)/r.
  \]
  With its committee halves, the adversary recovers:
  \[
  x=\frac{\mu_f+\mu_\gamma}{w_f+w_\gamma}.
  \]
  It can now sign a message neither honest actor approved. Committee-enforced slot reservation cannot protect against C17’s fully corrupt committee.
- **Fix:** Bind each ECDSA slot to one exact authorized leaf set and OR branch before use. A different set must use a different slot. Alternatively, add an independent actor-side mechanism that prevents conflicting evaluations even against a fully corrupt committee. Per-member “answer once” state is insufficient.

**F3 — The supplied DLEQ verifier accepts false PRF partials**

- **Severity:** major
- **Location:** §4.6; [vectors/check.py:428](/home/hoskinson/.cache/review3-bundle/blind/vectors/check.py:428); decisions 28, 41
- **Claim affected:** PRF fallback verification, fault attribution, C13, O18/O26
- **Failure scenario:** The vector’s Fiat–Shamir challenge hashes `ctx`, `A1`, and `A2`, but omits the claimed partial `Yi`.

  A malicious shareholder knowing `k = κ₀,i` chooses distinct scalars `r,u`, sets
  \[
  A_1=rG,\quad A_2=uH,\quad
  c=H_{\rm FS}(ctx,A_1,A_2),
  \]
  and then constructs
  \[
  z=r+ck,\qquad
  Y=\left(k+(r-u)c^{-1}\right)H.
  \]
  This false partial satisfies both implemented checks:
  \[
  zG=A_1+c(kG),\qquad zH=A_2+cY,
  \]
  although `Y ≠ kH`.

  The adversary can construct the proof before sending `Y`. On fallback, its proof passes; combination still produces the wrong key. The specified “`t` proved partials but failed tag” rule then blames the honest dealer and voids the request.

  This is a concrete defect in the supplied verifier. Correctly instantiated Chaum–Pedersen proofs do not have this defect.
- **Fix:** Bind the complete statement, particularly `Yi`, into the Fiat–Shamir challenge. Specify that transcript in the design and add this malicious-shareholder case to the vectors.

**F4 — Theorem D’s scalar-pseudorandomness statement omits its published verification value**

- **Severity:** major
- **Location:** §§4.6, 9.3, 12 O26; decisions 28, 40–41
- **Claim affected:** Theorem D restated; the justification for C9 and C18 secrecy
- **Failure scenario:** Open the header, which publishes `P_{v,g} = y_{v,g}G`, while leaving variant `(v,g)` unselected. No honest partial for that variant has been released.

  Given a challenge scalar that is either the real `y_{v,g}` or an independent uniform scalar `z`, distinguish them by checking:
  \[
  zG\stackrel{?}=P_{v,g}.
  \]
  The real value always passes; the independent value passes with probability `1/N_s`.

  Consequently, raw `y_{v,g}` cannot be indistinguishable from an independent uniform value given the actual protocol view. If O26 deliberately excludes the published `P`, its theorem is insufficient for the claimed application.
- **Fix:** State a joint hybrid that changes `y` and its published public key consistently, and prove contribution-encryption security given that public key. Separate this from pseudorandomness of an unrevealed symmetric body key. This finding does not itself establish plaintext recovery.

**F5 — Cold start can resurrect an already-used ECDSA slot**

- **Severity:** blocking
- **Location:** §§3.9, 7.11, 9.1 C16; decisions 6, 18
- **Claim affected:** C5, C12, C16; recovery nonce safety
- **Failure scenario:** At the latest Midnight checkpoint, slot `ℓ` is unused. After that checkpoint, a request uses it and releases a committee half for hash `h₁`. Before another checkpoint, the committee loses its recoverable board tail and local state.

  Section 7.11 restores slots from `E`, excluding only claims visible at the checkpoint and requests pending there. Slot `ℓ` passes that test. After the original request expires, a malicious holder obtains another authorized request on the restored slot, with hash `h₂`.

  The holder, or a colluding combiner, obtains:
  \[
  s_{f,1}=h_1w_f+r\mu_f,\qquad
  s_{f,2}=h_2w_f+r\mu_f.
  \]
  Subtraction reveals `w_f` and then `μ_f`. Combined with the holder’s slot halves, these reveal the address key; a holder knowing its address shard and tweak also obtains the permanent `x_f`.
- **Fix:** Restore an ECDSA slot only with durable evidence that it remained unused through the recovery cutoff. If the intervening history is unavailable, burn every previously usable slot whose non-use cannot be established and refill. A checkpoint replay floor alone is insufficient. O10/O17 must include this crash window.

**F6 — The envelope omits information actors need to recompute their contributions**

- **Severity:** blocking
- **Location:** §§4.2, 4.6, 5.9; decisions 23, 33, 36
- **Claim affected:** Executability of multi-actor signing and signer-set verification
- **Failure scenario:** An honest pool actor decrypts the specified header and capsules. They contain aggregate `R_A`, total nonce `R`, and other actors’ pool references, but no explicit initiator nonce `R₀`. The specified fields also omit the salt needed to recompute `pm`.

  Recovering `R₀` from `R_A` requires solving:
  \[
  R_A=R_0+\sum_a\left(D_a+
  H_{\rm bind}(CL(R_0),pm,\ldots)E_a\right).
  \]
  The binding factors depend on the unknown `R₀`; ordinary point subtraction cannot recover it. The actor therefore cannot perform §4.2’s mandatory reconstruction of `CL` and `ρ_a`. The non-TEE encoding also needs an explicit, complete signing-set/initiator description from which weights can be derived.
- **Fix:** Specify and serialize `R₀`, the required salts, and canonical signing-set metadata. The capsule’s redundant total `R` could be replaced by `R₀`. Recalculate frame capacities after defining the complete encoding.

**F7 — Embedded contributions create a cryptographic circular dependency**

- **Severity:** blocking
- **Location:** §§4.6, 5.9; decisions 34–35, 37
- **Claim affected:** The embedded-contribution construction and its two-commit path
- **Failure scenario:** An actor encrypts an embedded contribution using:
  \[
  KDF(eP_{v,g}\parallel E\parallel hd\parallel position).
  \]
  But `hd` hashes `body_0`, whose encrypted header contains that embedded ciphertext. Construction therefore requires:
  \[
  hd=H(\ldots,\operatorname{Enc}(\ldots,
      \operatorname{Enc}_{KDF(\ldots,hd,\ldots)}(s_a)),\ldots).
  \]
  Changing the candidate `hd` changes the contribution ciphertext, the header ciphertext, and hence `hd` again. No construction algorithm is given; this is a hash fixed-point problem.
- **Fix:** Define a separate contribution-context digest over immutable request fields that exclude embedded ciphertexts. Use that digest for contribution encryption, while retaining the final `hd` over the completed envelope. Alternatively, remove embedding until such an encoding is specified.

**F8 — Pre-QC witness entries can permanently obstruct a later valid ordering**

- **Severity:** major
- **Location:** §§5.2, 7.7; decisions 29, 38; O28
- **Claim affected:** Opening progress and the claimed witness/board-vote merge
- **Failure scenario:** An honest node votes for a proposal placing envelope `eid` at position `(h,p₁)`. Its peers persist the attached `open` witness entry and acknowledge it. Network scheduling prevents that proposal from obtaining a QC.

  A later view commits the envelope at `(h,p₂)`. The honest node now needs an `open` entry for the actual QC position, but the peers’ rule rejects a different digest for the same key. The earlier acknowledgements concern an uncommitted position.

  At `t = n − f`, withholding Byzantine nodes leaves no spare honest shareholder: even one honest node blocked this way can prevent opening.
- **Fix:** Obtain the final-position witness after the ordering QC, or define a safe provisional-entry replacement rule. Another option is an opening witness digest independent of proposal position, with ordering checked separately. O28 must explicitly cover abandoned proposals, not only successful commits.

**F9 — Schnorr tickets permit plaintext guessing before release**

- **Severity:** blocking
- **Location:** §§4.2, 6.1–6.2, 9.1 C10
- **Claim affected:** C10, B1/B2/B4; blindness until release
- **Failure scenario:** A non-TEE node knows a candidate input and its public Taproot key `Q`. The payment is one of two predictable transactions—for example, spending that input to either of two known destinations, with otherwise fixed fields.

  From the ticket’s `x(R)`, it computes each candidate sighash `m_b` and:
  \[
  c_b=H_{\rm BIP340}(x(R)\parallel x(Q)\parallel m_b).
  \]
  It checks whether `c̃ = c_b` or `c̃ = −c_b`. This identifies the transaction before any variant release. The salt in `pm` does not protect the separate, unsalted challenge equation.

  A random-oracle output is not independent of a message when the observer can query the oracle on candidate messages.
- **Fix:** Narrow the blindness claim to explicitly account for offline guessing and message entropy. Strong message-indistinguishability requires a different signing construction; the existing ticket cannot provide it merely by salting `pm`.

**F10 — The TEE-break table preserves secrecy beyond its threshold**

- **Severity:** major
- **Location:** §§9.1 C10/C21, 9.2, 10 B3
- **Claim affected:** C8, C10, C12, C21 and the “kept” column
- **Failure scenario:** Break `t` enclaves and read their epoch dealing keys. For an envelope that has not been ordered, decrypt `t` outer shares and reconstruct:
  \[
  \kappa_0=\sum_{i\in T}\lambda_i\kappa_{0,i}.
  \]
  Compute every header and variant key directly. No QC or honest-node release is needed.

  Thus C8 does not survive `t` broken enclaves, contrary to both affected rows of §9.2. Likewise, non-TEE C10/C21 cannot protect against all `n` corrupt nodes. An entirely corrupt committee can also reuse its nonce secrets, so C12 cannot remain in the all-`n` “kept” column.
- **Fix:** Apply the `< t` confidentiality bound consistently throughout the document. Remove C8 and C12 from the applicable rows and distinguish intact-TEE operator corruption from extracted node secrets.

**F11 — B6 equates broadcast with host-chain inclusion**

- **Severity:** major
- **Location:** §§5.6, 10 B6
- **Claim affected:** B6’s “MET” grade
- **Failure scenario:** An honest combiner submits a Bitcoin or Ethereum transaction to its RPC endpoint or peers. Those parties read it before a block includes it; it may remain pending or never be included. The egress proxy hides the sender’s network identity, not the transaction from recipients.

  Named actors also possess the unsigned transaction before broadcast, as §6.1 expressly states.
- **Fix:** State confidentiality until public broadcast, with the actor exceptions. If confidentiality until inclusion is required, mark it unmet without a separately specified inclusion mechanism.

**F12 — Offline network-created addresses cannot satisfy the mandatory birth proof**

- **Severity:** major
- **Location:** §3.1 steps 1 and 3; §10 R3
- **Claim affected:** The offline-holder birth path; completeness of C1’s construction
- **Failure scenario:** The holder is offline. A creator computes:
  \[
  X_u=U+Hq_{st}(e_cU)G.
  \]
  The creator knows the additive offset but not `u`, hence not `x_u`. The mandatory birth check nevertheless requires a fresh Schnorr proof under `x_u`, bound to the new point and birth context. The creator cannot produce it, and the offline holder has not produced it. The address cannot obtain its birth certificate.
- **Fix:** Require the holder online for that birth step, or specify a separate birth-verification relation based on a previously validated receive key and the derivation. The existing per-shard proof cannot simply be assumed available.

The status audit found **no claim still literally marked “proved” in §9.1**; decision 41 made the stated downgrades. However, several open items require specification changes before a proof is possible: O6/O27 need F1 resolved, O19 needs F2 resolved, and O26 needs F3/F4 resolved. O28 must cover F8. C4 inherits C17’s limitations; C6 should distinguish an honest node’s behavior from an unauthorized *completed* release, since a corrupt node can always disclose its own partial. C15/C16 should explicitly inherit the recovery and resharing dependencies O5/O10/O17. Keeping C11 board-first conditional on O29, C14 open under O5, and C19 open under O20 is appropriate.

Things checked and found sound:

- **Signing identities:** The BIP340 parity factors and placement of the address and Taproot tweaks sum to the intended signing key. The final equation matches [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki). The Ed25519 scalar equation is also consistent.
- **Access-structure algebra:** Products of Lagrange coefficients correctly reconstruct nested shares. The ideal ECDSA multiplication/correction algebra produces the stated additive coefficients.
- **PRF interpolation:** Valid partials interpolate to `κ₀·H_c(dd ‖ label)`; the construction avoids the ciphertext/key circularity for ordinary, non-embedded envelopes.
- **Optimistic combination and batching:** Verifying the final signature before checking individual shares is sound; [RFC 9591 §5.3](https://datatracker.ietf.org/doc/html/rfc9591#section-5.3) supports this approach. Independent 128-bit batch coefficients sampled after inputs are fixed give the intended negligible false-accept probability.
- **Counts and local nonce rules:** The `K = 8, L = 2` grid has 30 actor halves and four committee slots. Fresh actor pairs per half and burning reserved slots are appropriate, subject to the global-enforcement and recovery failures above.