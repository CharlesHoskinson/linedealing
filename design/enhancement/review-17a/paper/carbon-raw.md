VERDICT: changes_requested

## Findings

1. **ECDSA slot-precedence rule diverges from `spec/DESIGN.md`, introduces nonexistent obligation `O38`, and is internally inconsistent with opening checks and nullifier uniqueness**
   - **Severity:** BLOCKING
   - **Location:** Section 3.2 (`src/sec-construction.tex:31`), Section 3.4 (`src/sec-construction.tex:90`), Section 3.7 (`src/sec-construction.tex:139`), Section 4.1 (`src/sec-security.tex:78`), Section 4.2 Table 4 (`src/sec-security.tex:123-124`), Section 9 (`src/sec-limits.tex:9`), and Section 9.1 Table 8 (`src/sec-limits.tex:56`).
   - **Claim:** On ECDSA slots, precedence is not determined by board order at opening: a request has precedence on an ECDSA slot only while its authorization is in force and only when the slot lies under the slot root opened by that authorization's source; requests without an authorization in force void no ECDSA request and burn no ECDSA slot when they end; an authorized request can take an ECDSA slot from an earlier namer without an authorization, which later ends void with `SLOT_TAKEN` once its own authorization comes into force, and only the record's own sources can be that namer; and proving that this rule preserves `C12` and `C13` is open obligation `O38`.
   - **Reason with evidence:**
     1. **Disagreement with `spec/DESIGN.md`:** `spec/DESIGN.md` contains neither an authorization-gated ECDSA slot-precedence rule nor an obligation `O38` (Section 12 of `spec/DESIGN.md:1293-1331` lists obligations `O1` through `O37` / `O31` and ends at line 1331). Instead, `spec/DESIGN.md` specifies board-order precedence and burn-on-end uniformly for named slots:
        - `spec/DESIGN.md:306` (§4.1):
          > "The earliest request in board order that names a slot and is still live has **precedence** on it. Honest nodes refuse a later request that names a slot under the precedence of another request, even when the later request's authorization comes into force first. ... A named slot is burned when the request that had precedence on it ends or lapses, whether a partial was released on it or not, and it never returns to the pool."
        - `spec/DESIGN.md:493` (§4.7 item 3, checks after the header opens):
          > "3. This request has precedence on every slot it names (§4.1), and all points are distinct (§4.5). A node that finds a named slot under the precedence of an earlier live request posts VOID with reason SLOT_TAKEN."
        - `spec/DESIGN.md:1043-1044` (§9.1, `C12` and `C13`) likewise rely on board-order precedence (`§4.1`) with obligations `O27`, `O32`, and `O28` only, and no `O38`.
     2. **Internal contradiction with `OPENED` processing (Section 3.7 vs. Section 3.8):** `src/sec-construction.tex:153` states:
        > "The board orders and opens the envelope while the authorization finalizes."
        Yet `src/sec-construction.tex:139` ("Order and open") instructs each node immediately upon combining $t$ header partials to open $k_{\mathsf{hdr}}$:
        > "The node checks that the header is well formed, that this request has precedence on every slot it names, that all points are distinct, that the authorization is in force and commits to $\hd$ and the tickets, and in TEE mode that every recomputed sighash and challenge matches its ticket."
        In a normal ledger-first ECDSA spend, the envelope opens in $C + h$ while the ledger authorization is still finalizing over $F_M$ (`src/sec-eval.tex:68`). At opening time, its authorization is not yet in force, so under `src/sec-construction.tex:90` (*"A request therefore has precedence on an ECDSA slot only while its authorization is in force"*) the request does **not** have precedence on its own ECDSA slots when opened. An implementer applying the opening check of line 139 (or `spec/DESIGN.md:493`) will fail or `VOID` normal ledger-first ECDSA requests before `F_M` completes.
     3. **Internal inconsistency in the described race (Section 3.4 and Section 9):** `src/sec-construction.tex:90` states:
        > "The rule has a cost: an authorized request can take a slot from an earlier namer without an authorization, which ends void with \msg{SLOT\_TAKEN} once its own authorization comes into force, and only the record's own sources can be in that position."
        And `src/sec-limits.tex:9` states:
        > "The rule leaves one race: an authorized request takes a slot from an earlier namer without an authorization, which then ends void, and only the record's own sources can be that namer."
        First, anyone who knows an account's public ECDSA slot id can be an earlier namer without an authorization, as `src/sec-construction.tex:90` itself states five sentences earlier (*"anyone could name an account's slot ids in envelopes that need no authorization"*). Second, every authorization for a record state spends its unique nullifier $\nf$, and *"The ledger rejects a second authorization on one nullifier"* (`src/sec-construction.tex:153`), while P2 owner (`slr_own`) and seizure (`slr_G`) sources open disjoint slot roots (`spec/DESIGN.md:570`; `src/sec-construction.tex:88, 90`). Consequently, once a later request $r_2$ has an authorization in force for that record state and takes slot $\ell$, an earlier request $r_1$ against the same record state can **never** have *"its own authorization come[s] into force"* (the ledger rejects $r_1$'s duplicate $\nf$), and if $r_1$ instead targeted a successor nullifier $\nf'$, that successor state cannot exist on the ledger until $r_2$ has already ended and settled—by which time $r_2$ has already burned $\ell$.
   - **Suggested fix:** Synchronize `spec/DESIGN.md` (§4.1, §4.5, §4.7, §5.4, §9.1, §12) and the paper so both specify one ECDSA slot-precedence rule and obligation list; separate immediate `OPENED` structural checks (which run before $F_M$ completes) from authorization-dependent slot-precedence/admission checks (which wait until the authorization is in force or $\Delta_c$ expires); and rewrite the race explanation in `src/sec-construction.tex:90` and `src/sec-limits.tex:9` so it matches nullifier uniqueness and disjoint owner/guardian slot roots.

2. **Single-user frame sizes and per-actor byte growth in Table 6 contradict the claimed maximum signing set `|S|` for `P2TR, K = 8, L = 2`, and `spec/sizes.py` omits TEE single-user header fields**
   - **Severity:** BLOCKING
   - **Location:** Section 7, Table 6 (`src/sec-eval.tex:14-15, 22, 29`; macros `\estFrameUsedNine`, `\estFrameUsedSeventeen`, `\estActorBytes`, `\estActorBytesTEE`, `\estSetsEightTwoNine`, `\estSetsEightTwoSeventeen` in `src/results-split.tex:9-12, 21-22`).
   - **Claim:** Inside the fixed `16,384 B` envelope frame (`src/sec-construction.tex:98`), a `P2TR, K = 8, L = 2` request uses `11,422 B` at $n = 9$ and `11,843 B` at $n = 17$, each additional actor adds `790 B` in non-TEE mode and `943 B*` in TEE mode (excluding `495 B` paid once for the 15 keys $P_{v,g}$), and the largest signing set $|S|$ per frame (initiator included) at `P2TR, K = 8, L = 2` is **`7 / 5`** at $n = 9$ and **`6 / 5`** at $n = 17$.
   - **Reason with evidence:**
     1. **Non-TEE total overflows `16,384 B` at $n = 9$, $|S| = 7$:** `measure/BENCH.md:68` reports the exact prototype measurements reproduced in Table 6:
        > `| 9 | BIP340 | K=8, L=2 | 11422 | 748 | 64 | 4700 | 1680 | 4134 | 1285 | 790 | 2818 | 1711 |`
        Here `First other actor = 1285` (`= 495 + 790`) and `Next other actor = 790`. For $|S| = 7$ (the initiator plus 6 other actors), the required bytes are:
        $$11{,}422 + 1{,}285 + 5 \times 790 = 11{,}422 + 495 + 6 \times 790 = 16{,}657\text{ B} > 16{,}384\text{ B},$$
        which overflows the `16,384 B` frame by **273 bytes** (only $|S| = 6$, using `15,867 B`, fits on top of the `11,422 B` single-user frame). The discrepancy arises because `spec/sizes.py:12` (`base = 11136` at $n = 9$) budgets the 8 capsules at $8 \times (465 + 16) = 3{,}848\text{ B}$ (`286 B` smaller than `split_sizes`'s measured `Capsules = 4134` in `measure/BENCH.md:68`), and `tests/split_envelope.rs` (`measure/BENCH.md:84, 88`) used a smaller transaction/capsule fixture than `split_sizes`.
     2. **TEE mode omits TEE single-user header bytes and overflows at $n = 17$, $|S| = 5$:** `spec/sizes.py:9-12, 24-29` computes the base size using the non-TEE header (`hdr = 150 + 64 + 16 = 230 B`) even when `tee=True`, omitting all single-user TEE header fields required by `spec/DESIGN.md:461`:
        > "- in TEE mode v1: the intent, `X`, the leaf root, the commitment randomness `r_ic` and the salt seeds `salt_v`, so the enclave recomputes every sighash, every `pm` and every `c`..."
        Those fields add `X` (`33 B`), `leaf_root` (`32 B`), `r_ic` (`32 B`), and $K = 8$ 32-byte `salt_v` seeds (`256 B`), i.e., **`353 B` plus the serialized `intent`** before any other actor is added. On top of the `11,843 B` single-user request at $n = 17$, $|S| = 5$ (4 other actors at `943 B*` plus `495 B` for $P_{v,g}$) already consumes:
        $$11{,}843 + 495 + 4 \times 943 = 16{,}110\text{ B},$$
        leaving only `274 B` in the `16,384 B` frame—less than the `353 B + |intent|` of mandatory TEE header fields.
   - **Suggested fix:** Use one consistent transaction/capsule fixture across `split_sizes`, `tests/split_envelope.rs`, and `spec/sizes.py`; include the single-user TEE header fields (`intent`, `X`, `leaf_root`, `r_ic`, and $K \times 32\text{ B}$ `salt_v`) in `spec/sizes.py` and the TEE frame-used baseline; and update Table 6 so the reported base size, per-actor growth, and maximum $|S|$ satisfy $\text{base} + 495 + (|S| - 1)\cdot\text{per\_actor} \le 16{,}384$.

3. **Table 6 misattributes `BIP340, K = L = 1` signing-set measurements to `Solana` (`Ed25519`)**
   - **Severity:** BLOCKING
   - **Location:** Section 7, Prose and Table 6 (`src/sec-eval.tex:5, 26`; macro `\estSetsOneOne` in `src/results-split.tex:29`).
   - **Claim:** Table 6 (`src/sec-eval.tex:26`) reports, as unmarked prototype measurements:
     > `Ethereum or Solana, $K = L = 1$ & \multicolumn{2}{l}{\estSetsOneOne, both modes and both sizes}`
     where `\estSetsOneOne` is `29 to 33`.
   - **Reason with evidence:** Neither `measure/BENCH.md`, nor `spec/DESIGN.md`, nor `spec/sizes.py` contains signing-set capacity figures for **Solana (`Ed25519`)**. Both `measure/BENCH.md` and `spec/DESIGN.md` report `29` to `33` for **Ethereum (`ECDSA`) and `BIP340`**, not Solana:
     - `measure/BENCH.md:92-93`:
       > `| ECDSA K = 1, L = 1 | 33 / 30 | 32 / 29 |`
       > `| BIP340 K = 1, L = 1 | 32 / 29 | 31 / 29 |`
     - `spec/DESIGN.md:1155-1156`:
       > `| Ethereum K = 1, L = 1 | 33 / 30 | 32 / 29 |`
       > `| BIP340 K = 1, L = 1 | 32 / 29 | 31 / 29 |`
     Furthermore, using `measure/BENCH.md:73`'s actual serialized `Ed25519` (`K=1, L=1`, $n = 17$) numbers (`Frame used = 2074`, `First other actor = 492`, `Next other actor = 459`), adding the TEE per-actor overhead (`+37 B` for $K = L = 1$, giving `496 B` per actor) and the TEE single-user header fields (`intent`, `X`, `leaf_root`, `r_ic`, `salt_1`, $\approx 200\text{--}400\text{ B}$) leaves space for only `27` to `28` other actors (`|S| = 28` to `29`), dropping below `29` for realistic intents, and no prototype test in `measure/BENCH.md:86-93` measures Solana (`Ed25519`) signing-set capacity. (In addition, `\estActorBytesTEE` on line 15 of `src/sec-eval.tex` is marked `*` as an estimate, whereas the TEE half of lines 22–26 is unmarked.)
   - **Suggested fix:** Change the row label in `src/sec-eval.tex:26` from `Ethereum or Solana, $K = L = 1$` to `Ethereum or BIP340, $K = L = 1$` to match `measure/BENCH.md:92-93` and `spec/DESIGN.md:1155-1156`, or measure `Ed25519` (`Solana`) in `tests/split_envelope.rs`, record it in `BENCH.md` and `DESIGN.md`, and update the range accordingly.

4. **Incorrect byte formula `2t(33t + 32n)` for committee slot dealings and unmarked board-byte estimates in Section 7 and `src/results-split.tex`**
   - **Severity:** BLOCKING
   - **Location:** Section 7 (`src/sec-eval.tex:3, 5, 19`) and `src/results-split.tex:1-5, 16-17`.
   - **Claim:**
     1. `src/sec-eval.tex:5` claims (unmarked):
        > "The outer dealing is $33t + 32n + 229$ bytes, 748 at $n = 9$ and 1{,}169 at $n = 17$, and the dealings of one committee slot by its $t$ dealers are $2t(33t + 32n)$ bytes."
     2. `src/sec-eval.tex:3` and `src/results-split.tex:1-5` state that every figure not marked with `$^{\ast}$` (`\est{...}`) is a measurement of a serialized prototype object, and Table 6 (`src/sec-eval.tex:19`, `src/results-split.tex:16-17`) reports `\estBoardNine` (`about 47\,KB`) and `\estBoardSeventeen` (`about 110\,KB`) without `\est{...}`.
   - **Reason with evidence:**
     1. **Wrong slot-dealing byte formula:** At $(n, t) = (9, 7)$ and $(17, 12)$, the formula $2t(33t + 32n)$ (copied from `spec/sizes.py:35`) evaluates to **`7,266 B`** and **`22,560 B`**, which counts only the bare Feldman commitments and share ciphertexts of the two polynomials $(d_\ell, e_\ell)$ and omits every dealer's context, ephemeral encryption point $E$ (`33 B`), and encryption proof $\pi$ (`196 B`)—the very `229 B` included for the outer dealing in the first half of the same sentence. Both `measure/BENCH.md` and `spec/DESIGN.md` give the actual serialized prototype sizes:
        - `measure/BENCH.md:75-80`:
          > "Board slot posts include dealer context, ephemeral key and proof. Four slots are one batch per dealer; all t dealers are counted.
          > | 9 | 7 | 8351 | 30317 |
          > | 17 | 12 | 24612 | 92580 |"
        - `spec/DESIGN.md:1134-1135`:
          > "| Schnorr slot on the board (all `t` dealers) | 8,351 B with the dealer context, `E` and `π` | 24,612 B |
          > | Schnorr slots of one request, one message per dealer | 4 slots, 30,317 B | 4 slots, 92,580 B |"
        Thus $2t(33t + 32n)$ understates the measured one-slot dealing size by `1,085 B` (`13%`) at $n = 9$ and `2,052 B` (`8.3%`) at $n = 17$, and does not sum to the `30.3 KB` / `92.6 KB` slot component used in Table 6's `about 47 KB` / `about 110 KB`.
     2. **Unmarked estimates (`\estBoardNine`, `\estBoardSeventeen`):** `src/sec-eval.tex:5` explicitly notes:
        > "The board bytes per request add the measured frame and slot bytes to an estimate of the votes, under 1\,KB at $n = 9$ and under 2\,KB at $n = 17$."
        And `spec/DESIGN.md:1118` confirms that the prototype takes board ordering/votes as verified inputs so *"the vote ... rows of §11.1 ... are therefore **estimates**"*. Because `16,384 + 30,317 = 46,701 B` and `16,384 + 92,580 = 108,964 B` reach `about 47 KB` and `about 110 KB` by adding an unmeasured vote-size estimate, omitting `\est{...}` on `\estBoardNine` and `\estBoardSeventeen` in `src/results-split.tex:16-17` violates the paper's measurement/estimate convention (`src/sec-eval.tex:3`, `src/results-split.tex:1-5`).
   - **Suggested fix:** Replace `2t(33t + 32n)` in `src/sec-eval.tex:5` with the actual serialized sizes from `measure/BENCH.md:79-80` (`8,351 B` at $n = 9$ and `24,612 B` at $n = 17$ for one slot, or `30,317 B` and `92,580 B` for a 4-slot batch, including each dealer's context, $E$, and $\pi$), and mark `\estBoardNine` and `\estBoardSeventeen` with `\est{...}` in `src/results-split.tex:16-17`.

5. **Single-circuit suite-hiding claim and `$2^{18}$`-row PLONK bound are stronger than `spec/DESIGN.md` and internally inconsistent with the SHA-256 row budget and `O37`**
   - **Severity:** BLOCKING
   - **Location:** Section 3.8 (`src/sec-construction.tex:153, 159`), Section 7 (`src/sec-eval.tex:70`), and Section 9.1 Table 8 (`src/sec-limits.tex:34, 55`).
   - **Claim:**
     - `src/sec-construction.tex:153`: *"One circuit serves every suite, profile and grid size, so the record shows none of them."*
     - `src/sec-construction.tex:159`: *"The relations form one PLONK circuit at $2^{18}$ rows from the SHA-256, SHA-512 and Keccak gadgets of the ledger's proof library. Its row count and proving time are open (O4), and so is calling the gadgets from a ledger contract (O25)."*
     - `src/sec-limits.tex:34` (`O4`): *"The ticket circuit for the three suites at $2^{18}$ rows or fewer, with its proving time."*
     - `src/sec-limits.tex:55` (`O37`): *"Batched settlement in the authorization circuit: the path of a settlement leaf under a landed root and of each named pool key under a pool-key root, measured beside the ticket proof within $2^{21}$ rows..."*
   - **Reason with evidence:**
     1. **Stronger than `spec/DESIGN.md` and internally inconsistent across Section 3.8, `O4`, and `O37`:** `spec/DESIGN.md:1298` (`O4`) and `spec/DESIGN.md:1236` include an explicit fallback ceiling `k ≤ 21`:
        - `spec/DESIGN.md:1298`:
          > "| O4 | Ticket circuit | the circuit for the three suites is composed from the SHA-256, SHA-512 and Keccak gadgets of midnight-zk, a request with 32 tickets measures at `k ≤ 18` (limit `k ≤ 21`), and its proving time is measured on a server CPU and on the companion device |"
        - `spec/DESIGN.md:1236`:
          > "The circuit stays below the limit `k ≤ 21`. Measuring it is O4."
        `src/sec-construction.tex:159` asserts *"form one PLONK circuit at $2^{18}$ rows"* as an unqualified fact in the sentence right before admitting *"Its row count and proving time are open (O4)"*, and `src/sec-limits.tex:34` drops `(limit k ≤ 21)` to state `$2^{18}$ rows or fewer`, even while `O37` (`src/sec-limits.tex:55`) budgets the combined authorization + ticket circuit at `$2^{21}$ rows`.
     2. **Row budget does not add up for a single suite-hiding PLONK circuit:** In PLONK (`midnight-zk`), hiding the suite on the ledger (`src/sec-construction.tex:153`) requires a **single** verification key—meaning SHA-256 (BIP340/BIP341/BIP143), SHA-512 plus wide modular reduction $\bmod\,q_s$ (Ed25519), and Keccak-256 (Ethereum ECDSA) must all be present in the same circuit alongside the base authorization checks (`ic`, 32-entry `tkc`, `nf`, `rh`, fee ceiling, $S \in \Gamma$ [`O22`], ECDSA slot roots, settlement path, and pool-key paths [`O37`]). Yet `src/sec-eval.tex:70` and `spec/DESIGN.md:1226-1236` show that **100 SHA-256 compressions for a 30-half BIP341 spend alone** consume $100 \times 1{,}911 = 191{,}100$ (`about 190,000*`) of the $2^{18} = 262{,}144$ rows, leaving only `71,044` rows for 32-ticket SHA-512 + $\bmod\,q_s$, 32-ticket Keccak-256, and all base authorization, access-structure (`O22`), and Merkle-path (`O37`) constraints, with no row count given for SHA-512 or Keccak-256.
   - **Suggested fix:** Qualify `src/sec-construction.tex:153, 159` and `src/sec-limits.tex:34` (`O4`) so `$2^{18}$` rows (`k = 18`) is stated as an unverified target estimated solely from the 30-half BIP341 SHA-256 compression count (with `$2^{21}$` rows, `k ≤ 21`, as the circuit limit per `spec/DESIGN.md:1236, 1298, 1330`), and state explicitly that fitting all three suites' hash gadgets plus `O22` and `O37` into one suite-hiding circuit is open under `O4`, `O22`, and `O37`.

6. **Rounding discrepancy in `\estCpuSlotsSeventeen` (`14.49 ms` vs. `measure/BENCH.md` `14.483 ms`) creates a `0.01 ms` sum mismatch in Table 7**
   - **Severity:** NON-BLOCKING
   - **Location:** `src/results-split.tex:59` (`\estCpuSlotsSeventeen`) and Section 7, Table 7 (`src/sec-eval.tex:57-59`).
   - **Claim:** At $n = 17$, Table 7 reports `Request path, TEE mode = 2.47 to 2.93 ms`, `Slot replenishment, 4 slots = 14.49 ms`, and `Total = 16.96 to 17.41 ms`.
   - **Reason with evidence:** `measure/BENCH.md:53, 55-56` reports:
     > `| Request path with one block's votes | 2.359 ms | 2.927 ms | ... |`
     > `| Slot replenishment, 4 slots | 6.232 ms | 14.483 ms | (t/n)·slot_deal_message + (t − t/n)·slot_batch_verify |`
     > `| Total | 8.41 to 8.59 ms | 16.96 to 17.41 ms | path + slots |`
     `14.483 ms` rounds to `14.48 ms`, whereas `14.49 ms` (matching `spec/DESIGN.md:1210`) comes from recomputing $(12/17)\times 3.995 + (192/17)\times 1.033 = 14.4868\text{ ms}$ from 3-decimal rounded medians. Displaying `14.49 ms` alongside `2.93 ms` makes the high-end parts in Table 7 sum to `2.93 + 14.49 = 17.42 ms` instead of the reported `17.41 ms` (`2.927 + 14.483 = 17.410 ms`).
   - **Suggested fix:** Change `\estCpuSlotsSeventeen` in `src/results-split.tex:59` from `14.49\,ms` to `14.48\,ms` so it agrees with `measure/BENCH.md:55` (`14.483 ms`) and `2.93 + 14.48 = 17.41 ms`.

7. **Section 3.7 misstates the number of board commits *after* authorization finality**
   - **Severity:** NON-BLOCKING
   - **Location:** Section 3.7 (`src/sec-construction.tex:116`) vs. Section 3.8 (`src/sec-construction.tex:153`) and Section 7 (`src/sec-eval.tex:68`).
   - **Claim:** `src/sec-construction.tex:116` states:
     > "A request with no collection takes two board commits after its authorization is in force: the commit that orders the envelope and the commit that carries its admission votes."
   - **Reason with evidence:** In `spec/DESIGN.md:527` (*"The normal path of a request with no collection has two board commits: the commit that orders the envelope and the commit that carries its ADMIT votes"*), the ordering commit happens **in parallel** with ledger finality $F_M$, not after the authorization is in force (`spec/DESIGN.md:1166-1168`). Both `src/sec-construction.tex:153` (*"The board orders and opens the envelope while the authorization finalizes"*) and `src/sec-eval.tex:68` (*"the board orders and opens the envelope during $F_M$. In TEE mode post to broadcast takes $\max(F_M, C + h) + C + 4h$"*, i.e., $F_M + 1.2\text{\,s}^{\ast}$ when $F_M \ge C + h$) rely on only **one** board commit (`ADMIT`) occurring after $F_M$.
   - **Suggested fix:** Replace *"takes two board commits after its authorization is in force"* in `src/sec-construction.tex:116` with *"takes two board commits in total: the commit that orders the envelope (in parallel with authorization finality) and, once its authorization is in force, the commit that carries its admission votes"*.

8. **Omitted per-half salt derivation, variant-body KDF domain label, and TEE header fields in Sections 3.3 and 3.6**
   - **Severity:** NON-BLOCKING
   - **Location:** Section 3.3 (`src/sec-construction.tex:44`), Section 3.6 (`src/sec-construction.tex:104, 106`), and Section 3.7 (`src/sec-construction.tex:139`).
   - **Claim:** `src/sec-construction.tex:44` refers to *"a salt per variant, generation and input"*; line 104 writes *"For variant $v$ in generation $g$, $Z_{v,g}$ gives the body key $k_{v,g}$, the contribution secret $y_{v,g} = \Hq{q}(Z_{v,g} \,\|\, \texttt{ctb})$"*; and line 106 says each capsule holds *"the salt seed"* and in TEE mode the header *"also holds the intent and every weighted leaf point, so the enclave recomputes every sighash and checks every contribution"*.
   - **Reason with evidence:** `spec/DESIGN.md:319` defines per-half salts from a single 32-byte per-variant `salt_v` via `salt = H(salt_v ‖ g ‖ j)`; `spec/DESIGN.md:444` domain-separates the body key as `k_{v,g} = KDF(Z_{v,g} ‖ "body")`; and `spec/DESIGN.md:461, 494` requires the TEE header to also carry `X`, `leaf_root`, `r_ic`, and `salt_v` so the enclave can verify `ic` and recompute every `pm` as well as every challenge `c̃` upon opening (before any capsule key `ck_v` is derived at release).
   - **Suggested fix:** State $\mathsf{salt} = H(\mathsf{salt}_v \parallel g \parallel j)$ in Section 3.3, write $k_{v,g} = \KDF(Z_{v,g} \parallel \texttt{body})$ in Section 3.6, and list `X`, `leaf_root`, `r_ic`, and `salt_v` among the TEE header fields in `src/sec-construction.tex:106`.

9. **Minor omissions in TEE cold-start ECDSA slot burn (`bound` slots), `C18` secrecy adversary in Table 4, and Lean declaration phrasing**
   - **Severity:** NON-BLOCKING
   - **Location:** Section 3.9 (`src/sec-construction.tex:199`), Section 4.2 Table 4 (`src/sec-security.tex:129`), and Section 6 (`src/sec-formal.tex:3`).
   - **Claim:**
     1. `src/sec-construction.tex:199`: on a whole-committee restart without slot anchors, each node burns *"every unused slot of every ECDSA account pool"*.
     2. `src/sec-security.tex:129` (`C18`): lists the secrecy adversary as `|C| < t (non-TEE: |C| \le f)`.
     3. `src/sec-formal.tex:3`: *"The four modules have 58 declarations: 57 theorems and one equivalence, \lean{C17_threshold_completions_equiv}."*
   - **Reason with evidence:**
     1. `spec/DESIGN.md:872` and `spec/DESIGN.md:956` specify burning *"every `free` and `bound` slot"* in every ECDSA account pool on a whole-committee restart, so shares of `bound` slots from requests lost in the unanchored board tail are durably erased as well (`spec/DESIGN.md:930-938`).
     2. `spec/DESIGN.md:1049` specifies the `C18` secrecy adversary as *"`|C| < t` (non-TEE: `|C| ≤ f`, as C9) plus the actors other than the initiator"*, matching `C18`'s prose claim and `C9` (`src/sec-security.tex:120`).
     3. Across `lean/KeySplit.lean`, `lean/Access.lean`, `lean/Slots.lean`, and `lean/Profiles.lean`, there are 58 theorem/equivalence declarations (57 `theorem`s plus `def C17_threshold_completions_equiv : ... ≃ ...`, matching all 58 `#print axioms` entries in `lean/axioms-output.txt`), alongside 33 helper `def`s, 6 `inductive` types, 2 `structure`s, and 1 `instance` (100 total Lean declarations).
   - **Suggested fix:** Write *"every `free` and `bound` slot of every ECDSA account pool"* in `src/sec-construction.tex:199`, append *"and actors other than the initiator"* to `C18`'s secrecy adversary in `src/sec-security.tex:129`, and clarify *"58 theorem and equivalence declarations"* in `src/sec-formal.tex:3`.

## Checked and Found Sound

- **Lean 4 modules and axiom audit (`lean/KeySplit.lean`, `lean/Access.lean`, `lean/Slots.lean`, `lean/Profiles.lean`, `lean/axioms-output.txt`, Section 4.1 Propositions 1–7, Section 6):** Verified all 40 `\lean{...}` theorem/definition citations in `src/sec-security.tex` and `src/sec-formal.tex` against the `.lean` sources. Every quantifier, well-formedness premise (`wf`, `id_pos`, `NoDup`, `r ≠ 0`, `q = (n + f + 2) / 2`, `b ≤ f`), and conclusion in Propositions 1–7 and `C12_one_digest_per_slot` accurately reflects the mechanized Lean statements (including why $q = \lceil(n+f+1)/2\rceil$ makes $2q \ge n + f + 1$ hold over $\mathbb{N}$ without a separate $n > 3f$ hypothesis). Confirmed zero occurrences of `sorry`, `axiom`, or `native_decide`, and verified that all 58 entries in `lean/axioms-output.txt` depend only on `propext`, `Classical.choice`, and `Quot.sound`.
- **Cryptographic key-split, Taproot parity, FROST binding, and ECDSA session algebra (Sections 2.2–2.3, 3.1–3.6):** Verified BIP340/Taproot parity folding ($g = g_P g_Q$, single placement of $\ctil\,\tw + c\,g_Q t_{\mathsf{tap}}$ in $s_0$), Ed25519 un-clamped scalar linearity $\bmod\,q_s$, FROST two-nonce binding over $\CL$ and $\pmh$ (with one fresh $k_0$ and one distinct pool pair per half so pre-sealed unselected variants never reuse an actor nonce), rogue-key prevention via proofs of possession on every shard and offline key, ECDSA base-$R_\ell$ share verification $(a\varphi_i)R_\ell = \varphi_i R_f$ (including non-identity checks on $R_\ell$), ECDSA leaf-set binding (`prop:leafsets`), and full-statement Chaum-Pedersen DLEQ transcripts for threshold PRF partials.
- **Claim statuses and TEE-break degradation (Section 4.2 Table 4, Section 4.4 vs. `spec/DESIGN.md` §9.1–§9.2):** Aside from `O38` on `C12`/`C13` (Finding 1) and the minor `C18` adversary-column omission (Finding 9), all 21 claims (`C1`–`C21`), Open statement 8 (`stmt:prf`), and the enclave-compromise breakdown accurately preserve the `sketched` / `open` / `assumed` statuses, assumptions, and open obligations (`O1`–`O37`) of `spec/DESIGN.md` §9 without overclaiming Lean scalar lemmas as cryptographic proofs.
- **Thresholds, rollback bounds, latency, CPU medians, and ledger-write budgets (Sections 3.2, 3.8, 3.9, 7, 9 vs. `measure/BENCH.md` and `spec/DESIGN.md`):** Verified forked-board key-recovery thresholds ($3(t - |C|) \le n - |C| \implies 6, 10$ on Schnorr; $2(t - |C|) \le n - |C| \implies 5, 7$ on ECDSA with an admitted set), peer-witness rollback safety ($c \le n - 1 - 2f \implies 4, 6$), checkpoint byte counts ($88 + 52P + 64 + 8n + 8 + 32n + 64q = 1{,}008\text{ B}$ and $1{,}712\text{ B}$ for $P = 2$), latency formulas, and all individual Criterion benchmark medians, request-path ranges (`2.18 to 2.36 ms`, `2.47 to 2.93 ms`), totals (`8.41 to 8.59 ms`, `16.96 to 17.41 ms`), and per-core rates (`116 to 119`, `57 to 59` req/s) against `measure/BENCH.md` (save the `0.01 ms` rounding of `14.483 ms` in Finding 6).
- **Related work (Section 8, `src/sec-related.tex`, `src/refs-split.bib`):** Checked representations of line dealing (`LD`), FROST/Sparkle (`FROST`, `RFC9591`, `Sparkle`), presigning (`GS21`, `GS22`, `GG20`, `CGGMP21`, `Lan95`), network-custody MPC (`TwoPCMPC`, `FMMSS25`, `IkaDocs`, `CZC26`), bridge committees (`ckBTC`, `THORChain`, `tBTC`), TEE + MPC signing (`HOT`), and non-interactive VSS (`cgVSS`, `Groth21`); found them accurate and non-overclaiming.
