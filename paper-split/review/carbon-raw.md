VERDICT: changes_requested

## Findings

1. **Proposition 7 (`prop:profiles`) and Profile P0/P1/P2 Claims Overstate `Profiles.lean`, Contradict Section 2.3–2.4 Charter Forms, and Mismodel Profile P0**
   - **Severity**: BLOCKING
   - **Location**: Section 4.1 (`src/sec-security.tex`, lines 85–88); Section 2.4 (`src/sec-setting.tex`, lines 59–66); Abstract (`src/sec-abstract.tex`, line 6).
   - **Claim**: Proposition 7 states without charter restriction:
     > *"In each of P0, P1 and P2, every signing set that reaches the charter's formula with weights $\lambda$ gives, by one combination rule that takes no profile, a scalar $s$ with $s g = (k_f + \sum_a k_a)\,g + c\,(\xf + \tw + s_\Gamma)\,g$, where $s_\Gamma$ is the dealt secret. The user alone signs in every profile. P2 adds the guardian branch and changes nothing else: every P1 signing set is a P2 signing set, every P2 dealing is a P1 dealing, and a P2 signing set is a P1 signing set or a set of guardians. No set without the user covers a P0 or P1 charter, and $k$ guardians cover a P2 charter. Lean: `D19_signing_profile_free`, `D19_user_signs`, `D19_P2_extends_P1`, `D19_P2_signing_sets`, `D19_P1_no_seizure`, `D19_P2_guardians_seize`."*
     Section 2.4 (`src/sec-setting.tex`, line 66) further claims *"signing never reads the profile (\cref{prop:profiles})"*, and the Abstract (`src/sec-abstract.tex`, line 6) claims Lean checks *"the independence of signing from the profile"*.
   - **Reason with evidence**:
     1. **Missing single-user charter hypothesis (false for Section 2.3–2.4 charters and stronger than `Profiles.lean`)**: In `lean/Profiles.lean` (lines 19–25), the profile charter is hardcoded to a single leaf for P0 and P1 and a top-level OR with guardians for P2:
        ```lean
        def soleCharter (user : ι) : Gate q ι := leaf user

        def charter (user : ι) (guardian : ZMod q → ι) (ids : Finset (ZMod q)) (k : ℕ) :
            Profile → Gate q ι
          | .P0 => soleCharter user
          | .P1 => soleCharter user
          | .P2 => userOrG user guardian ids k
        ```
        By contrast, Section 2.4 (`src/sec-setting.tex`, lines 63–64) defines P1 as *"The key of (1) under any access structure"* and Table 1 (`src/sec-setting.tex`, lines 47–49) gives P1 charters $\mathsf{user} \wedge \mathsf{issuer}$ and $2\text{-of-}3\text{ officers}$, plus the regulated-custody charter $\mathsf{user} \wedge (\mathsf{custodian} \vee \mathcal{G})$. Without restricting Proposition 7 to the single-user charter (`soleCharter`), four of its assertions are false for the paper's own charters: `{user}` alone does not sign $\mathsf{user} \wedge \mathsf{issuer}$; two officers without `user` cover $2\text{-of-}3\text{ officers}$; $k = 3$ guardians alone do not cover $\mathsf{user} \wedge (\mathsf{custodian} \vee \mathcal{G})$; and $\{\mathsf{user}\} \cup T$ ($|T| = 3$ guardians) is neither a P1 signing set of $\mathsf{user} \wedge \mathsf{custodian}$ nor a subset of guardians.
     2. **Mismodeling of profile P0 (contradicts Section 2.4 and `DESIGN.md`)**: `lean/Profiles.lean` (lines 23, 27–36) assigns `.P0` the split key $(\xf + \tw + s) \bullet g$ and the split combination `(kf + c * xf) + c * tw + ...`. In the actual protocol, P0 is an existing owner key with no $\xf$, no $\tw$, and no committee nonce slots, and committee processing branches on the request type after `OPENED` into `[LD]`: Section 2.4 (`src/sec-setting.tex`, line 62) says *"The owner's existing key, dealt by line dealing [17] inside the envelope of Section 3.6. It gains blind ordering and no co-custody"*, and `spec/DESIGN.md` (§5.7, line 634; see also §1 line 25 and §4.6 line 476) states:
        > *"P0 spend: after OPENED the committee runs line dealing on the sealed lines in the header: anchor, lock, select, decrypt and combine. The P0 owner's line needs no committee half."*
   - **Suggested fix**: Restrict Proposition 7 explicitly to P1 and P2 in the single-user / guardian-seizure charter form ($\Gamma_{\mathrm{P1}} = \mathsf{user}$, $\Gamma_{\mathrm{P2}} = \mathsf{user} \vee \mathcal{G}$) on Schnorr algebra (or generalize `Profiles.lean` to arbitrary base $\Gamma_{\mathrm{P1}}$ with $\Gamma_{\mathrm{P2}} = \Gamma_{\mathrm{P1}} \vee \mathcal{G}$ where appropriate), remove P0 from the split-key combination claim, and qualify Section 2.4 line 66 and the Abstract so they state that P1 and P2 share one signing combination rule while P0 shares the envelope and ordering path up to `OPENED`.

2. **Proposition 1(b) (`prop:keysplit`) Omits the Degree/Length Bound $< t$ on the Commitment Family $C$, Rendering It False as Stated and Stronger Than `D21_reconstruct_point`**
   - **Severity**: BLOCKING
   - **Location**: Section 4.1 (`src/sec-security.tex`, lines 20–24); macro definition (`src/main.tex`, line 35).
   - **Claim**: Proposition 1(b) states:
     > *"For any family of committed points $C$ and any set $Q$ of at least $t > 0$ node indices, $\sum_{i \in Q} \lambda_{Q,i} \Eval(C, i) + \tw\,g + \sum_a X_a = C_0 + \tw\,g + \sum_a X_a$; no honest dealer is assumed. Lean: `D21_reconstruct_point`."*
   - **Reason with evidence**: Neither $\Eval(C, i)$ nor the length of the commitment family $C$ is defined anywhere in the paper (`\Eval` occurs only in `src/main.tex` line 35 and `src/sec-security.tex` line 22). In `lean/KeySplit.lean` (lines 28–31), `D21_reconstruct_point` is:
     ```lean
     theorem D21_reconstruct_point (A : Finset ι) (Q : Finset (ZMod q)) {t : ℕ} (ht0 : 0 < t)
         (ht : t ≤ #Q) (Cf : ℕ → G) (g : G) (tw : ZMod q) (X : ι → G) :
         ∑ i ∈ Q, lam Q i • feldmanEval t Cf i + tw • g + ∑ a ∈ A, X a = Cf 0 + tw • g + ∑ a ∈ A, X a := by
       rw [sum_lam_smul_feldmanEval Q ht0 ht]
     ```
     Here `feldmanEval t Cf i` evaluates $\sum_{j=0}^{t-1} i^j C_j$—specifically truncating `Cf` to the first $t$ commitments (degree $< t$)—over a set $Q \subseteq \mathbb{Z}_q$ of distinct field elements. For an unrestricted commitment family $C$ of length $> t$ (degree $\ge t$) with $|Q| = t$, Lagrange interpolation at $t$ points does not reconstruct $C_0$.
   - **Suggested fix**: Define $\Eval_t(C, i) = \sum_{j=0}^{t-1} i^j C_j$ explicitly in Section 4.1 (or restrict $C = (C_0, \dots, C_{t-1})$ to length $t$) and specify that $Q \subseteq \mathbb{Z}_q$ is a set of distinct node indices.

3. **Rogue-Key Equation in Section 3.1 Is Circular Under Hash-Derived $\tw$ and Disagrees with `DESIGN.md`, While Proposition 1(d) Omits That $\tw$ Must Be Fixed Independently of $X_r$**
   - **Severity**: BLOCKING
   - **Location**: Section 3.1 (`src/sec-construction.tex`, line 15); Section 4.1, Proposition 1(d) (`src/sec-security.tex`, line 26).
   - **Claim**: Section 3.1 states:
     > *"Without the proofs the last actor to publish chooses $X_r = zG - \Xf - \tw G - \sum_{a \neq r} X_a$ and knows the whole key $z$ (\cref{prop:keysplit})."*
     Proposition 1(d) states:
     > *"Without proofs of possession, for any $z$ the actor $r$ that publishes last can choose $X_r$ so that the address point is $z g$. Lean: `C2_rogue_key_without_pop`."*
   - **Reason with evidence**: By Section 2.2 (`src/sec-setting.tex`, line 19) and Section 3.1 (`src/sec-construction.tex`, line 11),
     $$\tw = \Hq{tw}(\Xf \,\|\, X_{a_1} \,\|\, \dots \,\|\, X_{a_r} \,\|\, \mathsf{charter\_id} \,\|\, \mathsf{seed}),$$
     which hashes every actor point $X_a$ (including $X_r$) together with a `seed` chosen by the coordinator *after* collecting the actors' points. Actor $r$ therefore cannot subtract $\tw G$ when picking $X_r$ without solving the hash fixed-point equation $X_r + \Hq{tw}(\dots, X_r, \dots)G = zG - \Xf - \sum_{a \neq r} X_a$, nor force the final address point $X$ to equal a pre-chosen $zG$. `spec/DESIGN.md` (§3.1, line 187) disagrees with Section 3.1's equation and states the attack accurately without $-\tw G$:
     > *"Without them the last actor to publish picks `X_r = z·G − X_f − Σ_{a≠r} X_a` and, with the other actors corrupt or not, holds a key the committee does not share in. ... The tweak does not replace the proofs, because `tw` is a function the attacker evaluates after choosing its point."*
     (That attack yields address point $(z + \tw)G$ and lets actor $r$ compute the full secret key $z + \tw$ once `seed` is shared, rather than forcing $X = zG$.) In `lean/KeySplit.lean` (lines 36–39), `C2_rogue_key_without_pop` quantifies `(tw z : ZMod q)` *before* `Function.update X r (z • g - Xf - tw • g - ∑ a ∈ A.erase r, X a)`, treating `tw` as an arbitrary constant independent of $X_r$.
   - **Suggested fix**: In Section 3.1 line 15, align with `DESIGN.md` §3.1: actor $r$ sets $X_r = zG - \Xf - \sum_{a \neq r} X_a$, giving $X = (z + \tw)G$, and learns the full key $z + \tw$ once `seed` is known because $\tw$ is a public function evaluated after $X_r$ is chosen. In Proposition 1(d), state explicitly that the Lean theorem takes a fixed scalar $\tw$ (or set $z' = z + \tw$).

4. **Slot Precedence and Open/Admit Checks Omit the Non-Burned Condition of `Slots.lean` (`BoardPrec`), Invalidating Proposition 5(a)–(c), Claim C13, and Within-Window Slot Rejection**
   - **Severity**: BLOCKING
   - **Location**: Section 3.2 (`src/sec-construction.tex`, lines 31, 33); Section 3.7 (`src/sec-construction.tex`, line 137); Section 4.1, Proposition 5 (`src/sec-security.tex`, lines 65–74); Section 4.2, Claim C13 (`src/sec-security.tex`, line 120).
   - **Claim**: Section 3.2 (line 31) defines: *"The earliest request in board order that names a slot and is still live has precedence on it, and honest nodes vote for no later request that names it"*, and Section 3.7 (line 137) specifies that on opening a node checks *"that this request has precedence on every slot it names"* (together with the checkpoint window $(h, h + B]$ in line 33). Proposition 5 (`src/sec-security.tex`, lines 70–72) claims in every reachable state:
     - (a) *"a request with precedence is the first request in board order that names the slot, and every honest vote is for that request"* (`D44_prec_first_namer`, `D44_honest_vote_first_namer`);
     - (b) *"two requests that each hold a quorum of votes are the same request"* (`D44_one_request_per_slot`);
     - (c) *"a request ordered after a request that names the slot never holds a quorum"* (`D44_later_never_reserves`).
     Claim C13 (`src/sec-security.tex`, line 120) claims a valid authorized envelope reaches `VOID` only *"because an earlier live request named one of its slots or a slot lies below the floor"*.
   - **Reason with evidence**: In `lean/Slots.lean` (lines 106–113), `BoardPrec` explicitly conjoins `¬ Burned names s`, where `Burned` holds as soon as *any* ordered request naming the slot has ended:
     ```lean
     def Burned (names : R → Bool) (s : State ι R) : Prop :=
       ∃ r, names r = true ∧ s.ord r ≠ none ∧ r ∈ s.ended

     def BoardPrec (names : R → Bool) (s : State ι R) (r : R) : Prop :=
       names r = true ∧ (∃ b, s.ord r = some b ∧
         ∀ r' b', names r' = true → s.ord r' = some b' → b' < b → r' ∈ s.ended) ∧
         r ∉ s.ended ∧ ¬ Burned names s
     ```
     Section 3.2's definition of precedence ("earliest ... and is still live") omits `¬ Burned`, and Section 3.7's open/admit check list omits checking that named slots are not locally burned (whereas `spec/DESIGN.md` §14.1 line 1313 requires *"VOID on burned slots"*). Without `¬ Burned`:
     1. Once an earlier request $r_1$ naming $\ell \in (h, h + B]$ ends (`VOID`, `EXPIRED`, or `FINAL`) within the 60 s interval before the next checkpoint advances $h$, a second request $r_2$ naming $\ell$ becomes *"the earliest request in board order that names a slot and is still live"*, falsifying Proposition 5(a), 5(b), and 5(c).
     2. An implementer coding the open/admit checks from Sections 3.2 and 3.7 lets honest nodes vote `OPENED`/`ADMIT` for $r_2$ on a slot whose shares were already erased when $r_1$ ended, burning named actors' pool pairs and stalling $r_2$ in `ADMITTED`.
     3. Even with `¬ Burned` enforced, Claim C13 omits reaching `VOID` because an earlier *ended* request burned a slot in $(h, h + B]$ after the latest checkpoint.
   - **Suggested fix**: Define precedence in Section 3.2 to require that no earlier ordered request has ever named the slot (equivalently, that the slot is unburned and no earlier live request names it, matching `BoardPrec` / `FirstNamer` in `Slots.lean`), add an explicit unburned check (`VOID` on burned slots) in Section 3.7 line 137, and replace *"earlier live request"* with *"earlier ordered request"* in Claim C13.

5. **Unauthenticated Board-Order Precedence and Burn-on-Naming Applied to ECDSA Slots Enable Trivial Account DoS and Permanent Bypass of P2 Guardian Seizure**
   - **Severity**: BLOCKING
   - **Location**: Section 3.2 (`src/sec-construction.tex`, line 31); Section 3.4 (`src/sec-construction.tex`, lines 82, 84); Section 3.5 (`src/sec-construction.tex`, line 92); Section 3.7 (`src/sec-construction.tex`, line 137).
   - **Claim**: Section 3.7 (line 137) opens every ordered envelope before its authorization is final and checks uniformly *"that this request has precedence on every slot it names"*, while Section 3.2 (line 31) states *"A named slot is burned when the request that had precedence on it ends, whether or not a partial was released"*, and Section 3.5 (line 92) claims P2 guardians contribute from reserved slots for a settled seizure.
   - **Reason with evidence**: Pre-ordering checks do not verify `auth_ref`, and headers open before authorization is in force (`src/sec-construction.tex`, lines 137, 151; `spec/DESIGN.md`, §4.6 line 432, §4.7 line 480, §5.3 line 543). For Schnorr committee slots, `DESIGN.md` (§4.1, line 304) explicitly acknowledges unauthenticated burn spam (*"Such an envelope needs no authorization, so a spammer can burn slots at the cost of one ordered frame per `G·L` slots"*) because committee pool slots are fungible and replenished by the committee alone. For ECDSA, however:
     1. Each address has only $N_{\mathsf{slot}} = 32$ per-address slots—including $G_g = 12$ guardian seizure slots in P2—and the birth/refill session runs in the clear on the board, exposing $X$ and every $R_\ell$ to all observers and to the P2 user (`src/sec-blindness.tex`, lines 14, 32; `spec/DESIGN.md`, §2.3 lines 119–120, §3.8 line 263, §6.4 item 3 line 772).
     2. `spec/DESIGN.md` itself is internally split between §4.1 line 304 (*"A named slot is burned when the request that had precedence on it ends"*) and §4.5 item 4 line 398 (*"A slot that a request reserved is burned when the request ends FINAL, VOID or EXPIRED"*), and the paper adopts only the burn-on-naming rule without distinguishing ECDSA slots from Schnorr pool slots.
     3. If an implementer applies §3.2 and §3.7 to ECDSA slots, any anonymous party—or a sanctioned P2 user who knows `slr_G`—can post a single unauthorized 16 KiB envelope naming an address's ECDSA slots (or all 12 guardian seizure slots). When that unauthorized envelope lapses to `VOID`, all named ECDSA slots burn; and because ECDSA refill requires every session party—including the P2 user—online (`src/sec-limits.tex`, line 9; `spec/DESIGN.md`, §5.8 line 645: *"the refill session needs every session party online, the user included. Until that refill runs, a user who stays offline delays a seizure on that address"*), a P2 user who self-burns `slr_G` and stays offline permanently defeats P2 guardian seizure. Even if ECDSA slots burn only upon *reservation* (`DESIGN.md` line 398), unauthenticated board-order precedence still lets an attacker keep bogus envelopes live for $\Delta_c$ blocks to repeatedly `VOID` legitimate ECDSA spends or seizures with `SLOT_TAKEN`.
   - **Suggested fix**: Separate ECDSA per-address slot reservation/burn rules from Schnorr committee-pool precedence in Sections 3.2, 3.4, and 3.7: require a valid in-force authorization (which proves membership of $\ell$ in `slr_own` or `slr_G`, Section 3.8 line 151) before an envelope can claim precedence on or burn an ECDSA slot.

6. **ECDSA Slot Session Construction Includes OR-Gate Escrow Holders as Session Parties and Misstates Group-Member Inputs, Disagreeing with `DESIGN.md` §3.6 and Corrupting $x_A$**
   - **Severity**: BLOCKING
   - **Location**: Section 3.4 (`src/sec-construction.tex`, line 70).
   - **Claim**:
     > *"ECDSA is not linear in the nonce, so the split is made in advance, in one interactive session per address among the committee and every session party: every actor that holds a top-level shard and every member of every group. Each session party $p$ enters with an additive part $x'_p$ of $x_A$ (an actor's shard, or $\lambda_{p,T_0} x_{\gamma,p}$ for a group member and a fixed subset $T_0$; party $1$ adds $\tw$)."*
   - **Reason with evidence**: This step disagrees with `spec/DESIGN.md` §3.6 (lines 216–220) on two requirements needed for $\sum_p x'_p = x_A$:
     1. `spec/DESIGN.md` (§3.6, line 216) states:
        > *"The session parties are every actor that holds a top-level shard and every member of every group. An escrow holder of an OR gate is not a session party (§3.8)."*
        In P2 ($\mathsf{user} \vee \mathcal{G}$) or regulated custody ($\mathsf{user} \wedge (\mathsf{custodian} \vee \mathcal{G})$), $\mathcal{G}$ is a $3$-of-$5$ group holding an escrow copy of the primary holder's shard; including members of $\mathcal{G}$ as session parties double-counts that shard in $\sum_p x'_p$.
     2. `spec/DESIGN.md` (§3.6, line 220) states:
        > *"Each party enters the session with an additive part `x'_p` of `x_A`: an actor's shard, or for a group member `λ_{p,T_0}·x_{γ,p}` for a fixed birth subset `T_0` of `k_γ` members (zero for the others)."*
        Section 3.4 omits both $|T_0| = k_\gamma$ and *"zero for the others"*. Having all $m_\gamma > k_\gamma$ group members enter nonzero values leaves $\lambda_{p,T_0}$ ill-defined for $p \notin T_0$ and fails to sum to $x_\gamma$.
   - **Suggested fix**: Update Section 3.4 line 70 to exclude OR-gate escrow holders from session parties and specify that for each threshold group $\gamma$ with a fixed $k_\gamma$-subset $T_0$, members $p \in T_0$ enter $\lambda_{p,T_0} x_{\gamma,p}$ and members $p \notin T_0$ enter $0$.

7. **Board-First Authorization Construction Omits Unspent-Nullifier Check, Root-Age Bound, and Ledger QC Gate Required by `DESIGN.md` §5.3 to Prevent Double-Spend Races**
   - **Severity**: BLOCKING
   - **Location**: Section 3.8 (`src/sec-construction.tex`, line 159); Section 4.2, Claim C11 (`src/sec-security.tex`, line 118).
   - **Claim**: Section 3.8 (line 159) specifies board-first authorization as:
     > *"A charter of profile P0, or of P1 whose predicates read no mutable ledger state, may let a node accept the authorization from the board: the node verifies the proof against a finalized ledger root and the board orders the nullifier first. The request then waits for no ledger finality."*
   - **Reason with evidence**: `spec/DESIGN.md` (§5.3, lines 581–585; §9.1 C11, line 1011) requires three critical checks omitted from Section 3.8:
     > *"2. Each node verifies the proof, checks that the root is a finalized Midnight root not older than the charter's bound minus a relay margin, so that the relayed call still lands within the bound, and checks that `nf` is unused in finalized Midnight state."*
     > *"5. The committee relays the call to Midnight with the QC of the block that ordered it. `FenrirAssets` accepts an `authorize` for a record of a board-first charter only with that certificate, so a direct call cannot race the board."*
     Verifying a ZK proof against a historical finalized root proves only that the record existed in that historical root, not that `nf` has remained unspent since then; and without the ledger contract rejecting direct `authorize` calls that lack a board QC on board-first charters, an owner can race a direct ledger `authorize` against a board-first `authorize` on the same `nf`, violating C11.
   - **Suggested fix**: Add to Section 3.8 line 159 that (i) nodes check `nf` is unused in current finalized ledger state and that the proof's root is within the bounded age minus a relay margin, and (ii) the committee relays `authorize` with the ordering QC and the ledger contract rejects direct `authorize` calls without a board QC for board-first charters.

8. **Claim C10 and Section 5 Overstate Operator and Observer Blindness in Both Non-TEE and TEE Modes, Contradicting Table 5, Section 3, and `DESIGN.md` §6 & §9.1**
   - **Severity**: BLOCKING
   - **Location**: Section 4.2, Claims C10 and C21 (`src/sec-security.tex`, lines 117, 128); Section 5 (`src/sec-blindness.tex`, lines 3, 12, 15–16, 26, 32).
   - **Claim**: Claim C10 (`src/sec-security.tex`, line 117) claims *"The views of Section 5"*. Section 5 states:
     - Line 26: *"Non-TEE blindness is blindness until release: a node cannot select, delay or refuse a request by its address, amount, destination or chain before it releases its share."*
     - Line 3: *"In TEE mode every cell of the operator's column after the post is ciphertext, sizes and timing, so the enclave's confidentiality carries the guarantee (C10, assumed)."*
     - Line 12 (Table 5, `Birth` row): *"Board observer and host chain: nothing"*.
   - **Reason with evidence**:
     1. **Non-TEE blindness statement (`src/sec-blindness.tex`, line 26) is false and contradicts Table 5, Section 3.2, and line 26 itself**:
        - *Address and chain on ECDSA*: Ten lines earlier, Table 5 (`Open`, line 16) states *"on ECDSA the slot ids name the account"* (`spec/DESIGN.md` §3.6 line 244, §6.1 line 729). Thus non-TEE nodes learn the exact ECDSA account $X$ and chain at `Open` before releasing any share, and $f + 1$ nodes can refuse or delay by address or chain.
        - *Chain / suite on every suite*: At `Open` (before release), the header reveals ticket size (36 B ECDSA vs. 149 B Schnorr), variant structure, and committee slot index $\ell$ from a suite-specific pool (`src/sec-construction.tex` line 23; `spec/DESIGN.md` §4.1 line 290: *"Each suite has its own pool"*), identifying the signature suite/chain before release.
        - *Enumerable candidate transactions*: Two sentences earlier in line 26, the paper notes that $\ctil$ is unsalted so a node that can enumerate candidate `(x(Q), m)` pairs finds the match before release (`spec/DESIGN.md` §9.1 C10 line 1010 explicitly restricts C10 to *"a node that cannot enumerate the candidate pairs `(x(Q), m)`"*).
     2. **TEE operator statement (`src/sec-blindness.tex`, line 3) is stronger than `DESIGN.md` §9.1 C10 and omits board-visible selection/refill leaks**: `spec/DESIGN.md` (§9.1 C10, line 1010) qualifies TEE C10 as:
        > *"TEE mode: operators see only ciphertext, sizes, timing, vote kinds (§6.4 item 15), the ECDSA slot sessions (§6.4 item 3) and the committee pool fields of the Midnight checkpoint (§6.4 item 16)."*
        Moreover, `spec/DESIGN.md` (§6.1, line 732) records that at `Anchor and select` both board observers and TEE operators see *"the selected index `j_g` per generation"* (omitted from Table 5), and mid-lifecycle ECDSA `SLOT REFILL` sessions run on the board in the clear (`DESIGN.md` §5.7 line 632). Similarly, Claim C21 (`src/sec-security.tex`, line 128) lists *"TEE: all operators"* and *"TEE: assumed"* while omitting the TEE claim clause present in `DESIGN.md` line 1021 (*"A TEE operator learns only the frame count, timing and the vote kinds of §6.4 item 15"*).
     3. **Table 5 (`Birth` and `Post and order`) contradicts Section 3.5, Section 3.8, and `DESIGN.md` §6**:
        - Table 5 line 12 claims a board observer sees *"nothing"* at `Birth`, contradicting Section 3.5 (`src/sec-construction.tex`, line 92: *"At birth the primary holder posts an escrow dealing to $\gamma$ in the open mode of line dealing... The members acknowledge on the board"*) and `spec/DESIGN.md` §6.4 item 3 (line 772: *"The guardian escrow dealings of §3.8 also show which addresses are P2"*), which expose OR-gate/P2 escrow dealings ($X_a$ and guardian `ACK`s, even on Schnorr suites) plus a 16 KiB `BIRTH` frame with `ACK` and no `ADMIT` (`DESIGN.md` §6.4 item 15, line 784) on the board.
        - Table 5 line 15 omits that board-first requests post `authorize` in the clear beside the envelope on the board (`DESIGN.md` §6.1 line 728, §6.4 item 9 line 778), and Section 5 omits `DESIGN.md` §6.4 item 13 (line 782: non-TEE nodes see offline holders' static receive key $U$ at birth, linking all network-created addresses of one holder).
   - **Suggested fix**: Qualify Section 5 line 26 to Schnorr suites with non-enumerable `(x(Q), m)` pairs and remove *"or chain"* (since `Open` reveals suite/tickets and ECDSA slot ids name the account); qualify Section 5 line 3 to match `DESIGN.md` C10 line 1010; add the TEE clause to C21 in Table 4; and add the `Birth` escrow/frame leaks, `Post and order` board-first `authorize` call, `Anchor and select` index $j_g$, and offline-holder receive-key $U$ link to Table 5 and Section 5's limits.

9. **Section 9 Overstates Non-TEE Collusion Resistance Against Actors When `slot_anchor` (O32) Is Absent, Contradicting Section 3.2 and Claim C5**
   - **Severity**: BLOCKING
   - **Location**: Section 9 (`src/sec-limits.tex`, line 3) vs. Section 3.2 (`src/sec-construction.tex`, line 35) and Section 4.2, Claim C5 (`src/sec-security.tex`, line 112).
   - **Claim**: Section 9 (`src/sec-limits.tex`, line 3) states:
     > *"An admitted signing set that colludes with $t$ committee nodes, in non-TEE mode or with $t$ broken enclaves, holds $x$. Covenants, vetoes and holds of P1 and P2 are therefore guarantees of an honest threshold, or of the TEE, and not of cryptography."*
   - **Reason with evidence**: In non-TEE mode without the unbuilt `slot_anchor` (open obligation O32), Section 3.2 (`src/sec-construction.tex`, line 35) and `spec/DESIGN.md` (§4.1 line 310, §10 R2 line 1062) show that a coalition $C$ with $f < |C| < t$ can fork the board to obtain $t - |C|$ honest partials on each of three distinct tickets on one Schnorr slot (or two on an ECDSA slot) and solve linearly for $\xf$:
     > *"A coalition with $f < |C| < t$ in non-TEE mode can certify conflicting board histories and show different honest nodes different requests on one slot. Three histories with distinct binding factors and challenges give three equations $\sigma_b s_f^{(b)} = d_\ell + \rho_b e_\ell + \sigma_b \ctil_b \xf$ in three unknowns and reveal $\xf$."*
     Partitioning the $n - |C|$ honest nodes across 3 Schnorr histories requires $3|C| + (n - |C|) \ge 3t \iff |C| \ge \lceil (3t - n)/2 \rceil$, which is **6 nodes** ($< t = 7$) at $n = 9, f = 2$ and **10 nodes** ($< t = 12$) at $n = 17, f = 5$ (and across 2 ECDSA histories requires $|C| \ge 2t - n$, i.e., **5** at $n = 9$ and **7** at $n = 17$). Once those $< t$ corrupt non-TEE nodes recover $\xf$, colluding with an admitted signing set gives them $x = \xf + x_A$ and bypasses all P1/P2 covenants, vetoes, and holds with fewer than $t$ nodes.
   - **Suggested fix**: Amend Section 9 line 3 to state that in non-TEE mode without `slot_anchor` (O32), fewer than $t$ corrupt nodes ($> f$, specifically $\lceil(3t-n)/2\rceil$ on Schnorr and $2t - n$ on ECDSA) can fork the board to recover $\xf$ and, with an admitted signing set, hold $x$; threshold-$t$ resistance in non-TEE mode requires O32.

10. **Section 1 ("What is not new") Claims ECDSA Slot Functionalities Are Instantiated by Published Protocols, Contradicting Section 3.4, Section 9, and `DESIGN.md` (O1, O2, O19)**
    - **Severity**: BLOCKING
    - **Location**: Section 1 (`src/sec-intro.tex`, line 22) vs. Section 3.4 (`src/sec-construction.tex`, line 74) and Section 9 (`src/sec-limits.tex`, lines 9, 31–32, 41).
    - **Claim**: Section 1 (`src/sec-intro.tex`, line 22) states:
      > *"The additive ECDSA halves of a slot are presignatures in the sense of Groth and Shoup [11], and the functionalities that prepare them are instantiated by published threshold ECDSA protocols (Section 3.4)."*
    - **Reason with evidence**: Section 3.4 (`src/sec-construction.tex`, line 74) states the opposite—that published protocols are merely *candidates* and their instantiation at $t = n - f$ and among many parties is open:
      > *"The candidates are the presigning of Canetti et al. [2] and the two-party emulation of 2PC-MPC [8] for $F_{\mathsf{presig}}$, and oblivious-transfer or Paillier-based multiplication for $F_{\mathsf{mul}}$. Their instantiation at $t = n - f$ is open (O1, O2), and so is the session among many parties (O19)."*
      `spec/DESIGN.md` (§1 line 42; §3.6 lines 222–224; §12 O1/O2/O19 lines 1232–1233, 1250) agrees with Section 3.4, noting in particular that Groth–Shoup's quadruple protocol (`GS22`, ePrint 2022/506) realizes $F_{\mathsf{presig}}$ at $t = f + 1$ only, whereas $F_{\mathsf{presig}}$ here requires Shamir shares at $t = n - f$ with Feldman commitments in base $R_f$ under $f$ Byzantine nodes.
    - **Suggested fix**: Change *"are instantiated by published threshold ECDSA protocols"* in `src/sec-intro.tex` line 22 to *"have published threshold ECDSA candidates whose instantiation at $t = n - f$ and among many parties is open (Section 3.4; O1, O2, O19)"*.

11. **Table 6 Signing-Set Size Figure for $K = L = 1$ (`59 or more*`) Disagrees with `DESIGN.md` §11.1 (`more than 60`)**
    - **Severity**: NON-BLOCKING
    - **Location**: Section 7, Table 6 (`src/sec-eval.tex`, line 26; macro `\estSetsOneOne` in `src/results-split.tex`, line 28).
    - **Claim**: Table 6 reports the largest signing set $|S|$ per 16 KiB frame for *"Ethereum or Solana, $K = L = 1$"* as `59 or more*` in both the $n = 9$ and $n = 17$ columns.
    - **Reason with evidence**: `spec/DESIGN.md` §11.1 (line 1123) reports `more than 60` for both columns:
      > *"| Ethereum or Solana `K = 1`, `L = 1` | more than 60 | more than 60 |"*
      Executing `python3 -I spec/sizes.py` outputs:
      - `n=9 K=1 L=1 ECDSA ... non: per actor 195, max others 74 (|S|<=75) | TEE: per actor 228, max others 63 (|S|<=64)`
      - `n=9 K=1 L=1 Schnorr ... non: per actor 202, max others 71 (|S|<=72) | TEE: per actor 239, max others 60 (|S|<=61)`
      - `n=17 K=1 L=1 ECDSA ... non: per actor 195, max others 72 (|S|<=73) | TEE: per actor 228, max others 61 (|S|<=62)`
      - `n=17 K=1 L=1 Schnorr ... non: per actor 202, max others 69 (|S|<=70) | TEE: per actor 239, max others 58 (|S|<=59)`
      Thus the paper's `59 or more*` matches `spec/sizes.py` (whose minimum is Solana at $n = 17$ in TEE mode with $|S| \le 59$), while `DESIGN.md` §11.1's `more than 60` is off by two at $n = 17$ TEE and disagrees with both `sizes.py` and Table 6.
    - **Suggested fix**: Reconcile `DESIGN.md` §11.1 with `sizes.py`, and in Table 6 consider reporting the exact `sizes.py` pairs (`75 / 64*` and `73 / 62*` for Ethereum; `72 / 61*` and `70 / 59*` for Solana) just as the preceding four rows do.

12. **Internal Arithmetic Discrepancy in Table 7 CPU Totals and Peer-Hop Latency Count in Section 7**
    - **Severity**: NON-BLOCKING
    - **Location**: Section 7, Table 7 & Latency (`src/sec-eval.tex`, lines 52–54, 63; `src/results-split.tex`, lines 40–45).
    - **Claim**: Table 7 lists `Request path, TEE mode` as `1.8 to 2.7 ms*` ($n = 9$) and `2.4 to 3.3 ms*` ($n = 17$), `Slot replenishment, 4 slots` as `1.2 to 3.6 ms*` ($n = 9$) and `2.0 to 7.2 ms*` ($n = 17$), and `Total` as `2.5 to 6.3 ms*` ($n = 9$) and `3.8 to 10.5 ms*` ($n = 17$). Latency (line 63) gives $\max(F_M, C + h) + C + 2h$ with *"three peer rounds for the partial exchange, the release witness and the release"* at one-way peer hop $h = 50\text{ ms}$.
    - **Reason with evidence**:
      1. In Table 7 (and `spec/DESIGN.md` §11.3, lines 1166–1168), the high ends add ($2.7 + 3.6 = 6.3\text{ ms}$; $3.3 + 7.2 = 10.5\text{ ms}$), whereas the low ends sum to $1.8 + 1.2 = 3.0\text{ ms}$ at $n = 9$ (not `2.5 ms*`) and $2.4 + 2.0 = 4.4\text{ ms}$ at $n = 17$ (not `3.8 ms*`) with no explanation of the $0.5$–$0.6\text{ ms}$ subtraction.
      2. In Section 7 line 63 (and `spec/DESIGN.md` §11.2, line 1134), `release witness` is counted as a single one-way hop $h$, whereas an acknowledged witness message takes a round-trip ($2h$), and Section 3.9 (`src/sec-construction.tex`, line 189) and `spec/DESIGN.md` (§7.7, line 893) specify:
         > *"A release therefore waits for the batched `release` round and two batched bind rounds, whatever the number of slots or requests at that height."*
         Three sequential peer round-trips before release equal $6h = 300\text{ ms}$ in TEE mode rather than $1h = 50\text{ ms}$.
    - **Suggested fix**: Either correct the low-end sums in Table 7 to `3.0 to 6.3 ms*` and `4.4 to 10.5 ms*` or state what shared/failure-path terms are excluded from the low-end total, and distinguish non-TEE latency (no peer witness) from TEE latency (three witness/bind round-trips = $6h$).

13. **Envelope Specification in Section 3.6 Omits Randomizing `auth_ref` for Non-Authorized Envelopes**
    - **Severity**: NON-BLOCKING
    - **Location**: Section 3.6 (`src/sec-construction.tex`, lines 96, 102, 110).
    - **Claim**: Section 3.6 claims every request type (`birth`, `spend`, `slot refill`, `contribution`, `P0`) shares one public shape so *"ordering is blind to the request type"* (line 96), and mentions `auth_ref` in $\eid = H(\hd \,\|\, \mathsf{auth\_ref})$ (line 102).
    - **Reason with evidence**: Section 3.6 never states what envelopes without a ledger authorization place in the public 32-byte `auth_ref` field. Leaving `auth_ref` zeroed would immediately distinguish `BIRTH`, `SLOT REFILL`, `CONTRIB`, and un-authorized `P0` frames before ordering. `spec/DESIGN.md` (§4.6, lines 417, 432) requires 32 random bytes (*"An envelope with no authorization carries 32 random bytes in `auth_ref`, so the field does not show the request type"*), though `DESIGN.md` §4.6 line 470 inconsistently says *"`auth_ref` zero"* for contribution frames.
    - **Suggested fix**: State in Section 3.6 that any envelope without a ledger authorization (`BIRTH`, `SLOT REFILL`, `CONTRIB`, and un-authorized `P0`) fills `auth_ref` with 32 uniform random bytes, and correct line 470 of `DESIGN.md` to match lines 417 and 432.

14. **Notation Collision in Related-Work Description of Langford (`Lan95`) and Uncited Bibliography Entry (`FR95`)**
    - **Severity**: NON-BLOCKING
    - **Location**: Section 8 (`src/sec-related.tex`, line 7); Bibliography (`src/refs-split.bib`, lines 114–123).
    - **Claim**: Section 8 (line 7) states: *"Langford deals shares of $k$ and $kx$ for each future signature to signers who answer with one linear partial [16]."*
    - **Reason with evidence**: Throughout the paper (`src/sec-intro.tex` line 5; `src/sec-construction.tex` lines 70–72), $k$ is the discrete logarithm of $R = kG$, so linear partials require shares of $k^{-1}$ and $k^{-1}x$. Langford's CRYPTO '95 paper (*"Threshold DSS Signatures without a Trusted Party"*) defines $r = (g^{k^{-1}} \bmod p) \bmod q$ so that $s = k(m + xr) \bmod q$ (and removes the trusted dealer of its Section 2 warm-up in Section 3). Using *"shares of $k$ and $kx$"* without noting Langford's inverted exponent convention clashes with the paper's notation. Separately, `@inproceedings{FR95, ...}` in `src/refs-split.bib` (lines 114–123) is never cited in `src/*.tex`.
    - **Suggested fix**: Clarify that in the paper's notation ($R = kG$) Langford prepares shares of $k^{-1}$ and $k^{-1}x$ (written $k$ and $kx$ under $r = g^{k^{-1}}$), and either cite or remove `FR95`.

15. **Broken `cleveref` Shared-Counter Labels Render Propositions 1–7 and Open Statement 8 as "Theorem 1"–"Theorem 8" in `main.pdf`, Plus Minor Lean Count Mismatch**
    - **Severity**: NON-BLOCKING
    - **Location**: Preamble (`src/main.tex`, lines 13, 21–29); Section 1 (`src/sec-intro.tex`, line 20); Section 6 (`src/sec-formal.tex`, line 3); Section 9 (`src/sec-limits.tex`, line 45).
    - **Claim**: In `main.pdf`, every `\cref{prop:*}` renders as `Theorem 1`–`Theorem 7`, and `\cref{stmt:prf}` in O26 (`src/sec-limits.tex`, line 45) renders as *"a written proof of Theorem 8"*, referring to `Open statement 8 [Open, O26]` (`src/sec-security.tex`, line 142) as a "Theorem". Additionally, Section 1 (line 20) says *"58 theorems"*, while Section 6 (line 3) says *"The four modules have 58 declarations: 57 theorems and one equivalence"* (the four `.lean` files contain 100 declarations total, of which 58—57 `theorem`s plus `noncomputable def C17_threshold_completions_equiv`—are the proof/equivalence items checked in `lean/axioms-output.txt`).
    - **Reason with evidence**: `src/main.tex` loads `\usepackage[capitalise,noabbrev]{cleveref}` on line 13 before defining `\newtheorem{proposition}[theorem]{Proposition}` and `\newtheorem{statement}[theorem]{Open statement}` on lines 21–27 without `thmtools` or `aliascnt`, causing `cleveref` to read only the shared `theorem` counter name.
    - **Suggested fix**: Load `thmtools` (or `aliascnt` with `\crefalias`) before `cleveref` so propositions and open statements are cross-referenced as `Proposition` and `Open statement`, and harmonize Section 1 and Section 6 to say *"57 theorems and one equivalence"*.

---

## Checked and Found Sound

- **Lean 4 Hygiene and Axiom Footprint (`lean/*.lean`, `lean/axioms-output.txt`)**: Verified that none of the four Lean modules (`KeySplit.lean`, `Access.lean`, `Slots.lean`, `Profiles.lean`) uses `sorry`, `axiom`, or `native_decide`, and that all 58 proof/equivalence items in `lean/axioms-output.txt` depend solely on `[propext, Classical.choice, Quot.sound]`.
- **Signature Split Algebra Across BIP340, Ed25519, and ECDSA (`src/sec-setting.tex` §2.2–2.3, `src/sec-construction.tex` §3.1, §3.3–3.4, `lean/KeySplit.lean`)**: Checked all parity cases $(g_P, g_Q, \sigma) \in \{\pm 1\}^3$ of BIP340 Taproot key-path signing ($d = g x_A + g_Q t_{\mathsf{tap}} + g \xf$, single placement of $\ctil \tw + c g_Q t_{\mathsf{tap}}$ in $s_0$, folded challenge $\ctil = g c$), Ed25519 scalar linearity without seed clamping, ECDSA slot-session share corrections and base-$R_\ell$ public DLEQ check $(a \varphi_i) R_\ell = \varphi_i R_f$, and `KeySplit.lean` parts (a), (c), (e)–(h).
- **Nested Access-Structure Reconstruction and Scalar Secrecy (`lean/Access.lean`, Propositions 2 and 3)**: Verified that `Reach`, `Covers`, `Dealt`, and `WellFormed` (nonzero distinct member ids and leaf-disjoint gate children) in `Access.lean` match Propositions 2 and 3, including both directions of covering/reaching (`D22_reach_covers`, `D22_covers_reach`), recursive Lagrange reconstruction (`D22_access_weighted_sum`), existential scalar secrecy over arbitrary well-formed nested gates (`C17_access_secrecy`), and the degree-$< k$ polynomial completion bijection (`C17_threshold_completions_equiv`).
- **ECDSA Leaf-Set Binding and Cold-Start Slot Burn (`lean/Slots.lean`, Propositions 4 and 6)**: Verified that `D43_two_subsets_reveal_line`, `D43_line_gives_key`, `D43_bound_slot_refuses`, `D43_one_full_request`, `D43_without_binding_two_full`, `C16_cold_start_no_reuse`, and `C16_without_burn_reuse` match Propositions 4 and 6 with exact hypotheses (including $r \ne 0$ for $\mu(0)$ and $k \ne 0$ for key recovery), and verified that quorum intersection in `Slots.lean` (`quorum n f = (n + f + 2) / 2`) holds unconditionally for all $n, f \in \mathbb{N}$.
- **TEE Peer-Witness Rollback and Cloning Bound (`src/sec-construction.tex` §3.9, `spec/DESIGN.md` §7.7)**: Verified the pigeonhole intersection bound $2w - (n - 1) = n - 1 - 2f$ for $w = n - 1 - f$ among $n - 1$ distinct peer `node_id`s, confirming safety for $c \le n - 1 - 2f$ ($4$ at $n = 9$, $6$ at $n = 17$) against both disk rollback and live VM cloning, as well as liveness with $f$ faulty peers ($n - 1 - f$ honest peers remain).
- **Claim Statuses and Open Obligations (`src/sec-security.tex` Table 4, `src/sec-limits.tex` Table 8, `spec/DESIGN.md` §9 & §12)**: Checked every claim C1–C21 and Open Statement 8 against `DESIGN.md` §9.1–9.3 and §12; verified that the C3 single-user Schnorr ROM simulation/forking sketch produces the exact challenge distribution with parity retry and fresh random-oracle query $(x(R^*), x(Q), m^*)$, that Chaum–Pedersen DLEQ challenges hash the partial $Y_{i,\mathsf{lab}}$ (`DESIGN.md` §4.6), and that all 23 open obligations cited in the paper (`O1`–`O6`, `O8`, `O10`, `O12`, `O17`, `O19`, `O20`, `O22`, `O25`–`O29`, `O31`–`O35`) are accurately tracked and never upgraded to proved status.
- **Byte-Budget Script (`spec/sizes.py` vs. `src/results-split.tex` and `src/sec-eval.tex`)**: Executed `spec/sizes.py` and verified all fixed field sizes, outer-dealing formulas ($33t + 32n + 229$), slot-dealing sizes ($2t(33t + 32n)$), per-actor envelope growth (`758 B` / `911 B`), contribution frames (`2.8 KB` / `3.2 KB`), embedded contributions (`1.7 KB`), and signing-set capacities across $n \in \{9, 17\}$ (flagging only the `DESIGN.md` §11.1 discrepancy in Finding 11).
