# Lead decisions for the merge

Inputs: protocol proposals `astra/PROPOSAL.md`, `carbon/PROPOSAL.md`, `fable/PROPOSAL.md`; Veritee hardening `hardening/{astra,carbon,fable}/HARDENING.md`; digest `VERITEE-MODEL.md`; briefs `BRIEF.md`, `BRIEF-VERITEE.md`.

Each decision names the lanes it follows and the reason.

## Protocol

1. **Key split.** Schnorr and Ed25519: additive `X = X_u + X_f + tw·G` (all three lanes). ECDSA: additive `x = x_u + x_f + tw` with a pool of one-use presignature slots prepared in an interactive session at address creation (Astra, Carbon). Reason: two lanes agree, it keeps one key algebra for all suites, and the brief allows one-time setup interaction. Fable's multiplicative split `x_u·(X_f + δG)` is recorded as the alternative. The committee side of slot generation at `t = n − f` (threshold multiplication) is an open item with named candidates.
2. **Committee half.** One root key `x_f` per curve from one DKG, Shamir at `t = n − f`. Each address uses a secret per-address tweak; the tweak reaches the committee only inside the sealed request (Carbon, Fable). Reason: no per-address DKG, rotation reshares O(1) secrets, and addresses do not link on chain. Astra's per-address DKG is rejected for its cost.
3. **The owner's one move.** The owner deals sealed user half-signatures, one per variant of a fee grid that spends one pinned input or nonce (all three lanes). The committee adds its half. Sealed mode's guarantee carries over: all n nodes corrupt cannot sign outside the dealt variants, and never learn `x_u`.
4. **Reading of R1.** No spend unless one of the charter's three sources authorizes it, the authorization settles on Midnight, and the source contributes its own key element. The committee holds no source's element (Fable's reading, with Carbon's destination pinning). Seizure goes only to the charter sink `D_reg`, exit only to the standing exit record `D_exit`.
5. **Seizure.** For charters with `seizable = true`, the user's half is escrowed at address creation to an independent guardian set G (3 of 5, disjoint from Fenrir operators). G produces a user half-signature only for a settled Midnight seizure, paid to `D_reg` (Astra, Fable). Regulated tokens also use asset-level controls (ERC-3643 forced transfer and freeze, Token-2022 permanent delegate and freeze authority) (Carbon). Carbon's vault contracts for native coins are rejected as the default: they break the native single-key output. They stay an option for a charter that demands on-chain seizure of native coins.
6. **Recovery when Fenrir disappears.** The universal path is an independent recovery group E (3 of 5, disjoint from G and Fenrir) that holds a verifiable backup sharing of `x_f` plus the unused committee slot state, and reprovisions a successor committee after a charter-defined Midnight delay (Astra). A Bitcoin Taproot exit leaf `<T_exit> OP_CSV <K_exit>` is a charter option for unregulated assets (Carbon, Fable). State plainly that a matured exit leaf ends the hold for that coin.
7. **Blindness on the board.** The request travels as a fixed-size padded envelope. Its data key is dealt by the owner as a Feldman-committed `t`-of-`n` sharing to the nodes' dealing keys `PK_i`, using SCHEME's existing encryption and public complaint, and shares move only after the quorum certificate fixes order (Fable). The same object serves TEE and non-TEE mode. Carbon's committee BLS12-381 threshold IBE key and Astra's outer threshold ciphertext are rejected: each adds a DKG and an assumption that the dealer-based envelope does not need.
8. **Covenant enforcement.** Midnight's authorize circuit proves the charter predicate with a private source tag and checks the hold accumulator. Nodes verify the settled authorization before they release a share. TEE mode: the enclave enforces it even if every operator is malicious, while the TEE holds. Non-TEE mode: holds and vetoes are honest-threshold; `t` corrupt nodes can release a user's already-dealt variants despite a later hold. Say so (Astra).
   - Drivers: R1 (no spend without an admitted source), C6, C7; the TEE and non-TEE modes of the brief.
   - Considered options: the entry records no alternative. It follows Astra's proposal.
   - Outcome and authority: the entry text, lead decision for the merge.
   - Consequences: in non-TEE mode holds and vetoes are honest-threshold, and `t` corrupt nodes can release already-dealt variants despite a later hold.
   - Confirmation: conformance, Lean oracle (LOOP item 13) refuses release without an in-force authorization (RQ-024, RQ-030, AU-010); outcome, Quint model (LOOP item 14) invariant C6 and C7.
   - Revisit when: a non-TEE mechanism makes holds hold against `t` corrupt nodes.
9. **Blind signing in non-TEE mode.** Nodes sign address-free tickets and verify a hash-only STARK (one BLS12-381 wrap, under 2^21 rows) that each ticket is the sighash challenge of an admitted transaction (Fable). In TEE mode v1 the enclave recomputes the sighash; the proof replaces it later behind the same interface.
10. **Requirement grading.** Grade honestly per mode, as Astra and Fable do. Carbon's all-MET table is rejected. B5 (unlinkability against the host chain graph) is PARTIAL at best with native outputs.

## Veritee hardening

11. **Close the attestation oracle first.** Evidence carries a class byte; caller-chosen payloads get only the public class; internal classes are served on a Unix socket; TPM quotes carry qualifying data (all three lanes).
12. **Verification without MAA.** Committee peers verify raw SNP and HCL evidence in the guest. MAA and the Warden are not in the signing trust base (Carbon, Fable).
13. **Sealed storage.** `/mnt/persist` becomes dm-crypt with dm-integrity under a vTPM key sealed to PCR 4, PCR 15 (post-setup) and a new PCR 14 for the committee role. Secrets inside use `K_seal = HKDF(K_tpm ‖ K_grp ‖ ratchet)`, where `K_grp` is a peer-released threshold PRF output that peers release only to a boot holding the current Midnight boot ticket (Fable, Carbon). Nonces and presignature state never reach disk. SNP-derived keys are rejected: the Azure paravisor hides `MSG_KEY_REQ` and binds it to the paravisor, not the image.
14. **Rollback and clones.** Every boot needs a Midnight boot ticket with counter + 1, which fences clones and superseded instances (all three). Before a PREVOTE, a partial signature, a decryption share or a sealed release leaves a node, `q = 6` peer enclaves witness `(node, rid, g) → digest` and refuse a second digest (Fable, Carbon). Midnight checkpoints of board state set the replay floor. A release that waits until a Midnight checkpoint root covers its witness entry is a high-value profile, not the default (Astra's Midnight finality before every output, in the batched form of entry 52).
15. **Offline encryption to the committee.** Each node generates its static epoch keys in the guest (X25519 HPKE key, SCHEME dealing key `PK_i`, board post key) under a reserved evidence class. Peers verify them and the epoch key set is recorded on Midnight. A wallet reads one record and encrypts once (all three).
16. **Secret release.** Committee secrets exist only through DKG, reshare and peer repair between attested enclaves. TLS keys are generated in the guest (ACME TLS-ALPN-01 or the internal CA). Operator inputs arrive only sealed to an attested provisioning key. Key Vault and managed identity are removed from committee images. Azure Secure Key Release is rejected as the gate, because the operator controls its policy and identity (Fable, Carbon; Astra's broker becomes the peer quorum).
17. **Erasure.** zeroize, mlock, no swap, no core dumps, `PR_SET_DUMPABLE=0`, and key destruction by ratchet and per-epoch group secret (all three).
18. **Whole-committee cold start.** Must be specified: what survives if all nine nodes reboot at once. Take the lanes' answer if one exists; otherwise define a cold-start path through the recovery group E and Midnight checkpoints.

## Owner ruling 2026-11-14: seizure is optional

Owner: "We have to have the ability to use fenrir with or without this mode." Seizure, freeze, blacklist, reversal and legal holds are a per-charter option, never a property of the protocol. Source trace: the book's three authorization sources and its "seize entry" (charter-conditional, custody levels L2/L3), plus one meeting line conditional on a federated sequencer (L08a-R10). The brief over-stated it as unconditional.

19. **Charter custody profiles.** Every address carries a profile fixed at birth in its charter:
   - `P0 existing`: the original line dealing on an existing owner address. No Fenrir co-custody, no holds, no seizure (book level L0).
   - `P1 co-custody`: split-line dealing, user half plus Fenrir half. Covenant predicates and approver vetoes the owner chose apply; no seizure, no third-party freeze, no guardian escrow. Exit to the standing exit record is unconditional when Fenrir disappears (recovery group or exit leaf).
   - `P2 regulated`: P1 plus the charter's seize, freeze, blacklist and hold entries, the guardian escrow G and the hold accumulator; exit is subordinate to a live hold.
   The protocol, envelope and committee state machine are identical across profiles; P2 only adds authorization sources and checks. Nothing in P0 or P1 depends on G, `D_reg` or the hold accumulator, and no P2 component is needed to run Fenrir.
   - Drivers: owner ruling 2026-11-14 ("use fenrir with or without this mode"); R1; the book's custody levels L0, L2, L3.
   - Considered options: (a) seizure as a property of every address, as the brief first stated it; (b) per-charter profiles P0, P1, P2 fixed at birth.
   - Outcome and authority: (b), owner ruling 2026-11-14.
   - Consequences: one protocol, envelope and state machine for all profiles; P2 adds sources and checks only; no P2 component is needed to run Fenrir.
   - Confirmation: conformance, Lean oracle (LOOP item 13) runs P0 and P1 requests with no G, `D_reg` or hold state (AU-006, RQ-066); outcome, Quint model (LOOP item 14) checks C11 per profile.
   - Revisit when: the owner adds or removes a profile.
20. R1 is read per profile: P0 and P1, no spend without the owner's own authorization (the owner's half-signature); P2, no spend without one of the charter's admitted sources.
   - Drivers: owner ruling 2026-11-14 on optional seizure; requirement R1.
   - Considered options: the entry records no alternative. It follows from entry 19.
   - Outcome and authority: the entry text, owner ruling 2026-11-14.
   - Consequences: P0 and P1 spends need the owner's half-signature; P2 spends need one of the charter's admitted sources.
   - Confirmation: conformance, Lean oracle (LOOP item 13) refuses a P1 request without the owner's statement (AU-005 to AU-007); outcome, Quint model (LOOP item 14) invariant C11.
   - Revisit when: entry 19 changes.

## Owner ruling 2026-11-14: n shards, arbitrary actors

Owner: "Allow for a split into n shards so we can have arbitrary actors involved in the production of a transaction. Fenrir does the MPC and the outside parties provide the shard."

21. **Multi-shard split.** An address key is `x = x_f + tw + Σ_{j∈A} x_j` over a set `A` of outside shard holders (the user, an issuer, a custodian, an approver, a guardian group, a regulator, any party the charter names). Fenrir holds only `x_f` and runs the MPC. Each outside actor holds its shard and contributes one sealed half-signature per variant, offline, with one move. The user half of P1 is the case `|A| = 1`.
   - Drivers: owner ruling 2026-11-14 ("split into n shards ... Fenrir does the MPC and the outside parties provide the shard"); R1, R2.
   - Considered options: (a) one user half only, the design before the ruling (the case `|A| = 1`); (b) `x = x_f + tw + Σ_{j∈A} x_j` over any set of outside actors.
   - Outcome and authority: (b), owner ruling 2026-11-14.
   - Consequences: every actor contributes one sealed half per variant with one move; actor nonce pools and contribution collection follow (entries 23, 34 to 36).
   - Confirmation: conformance, Lean oracle (LOOP item 13) recomputes `X` from the shard points (SH-006); outcome, Quint model (LOOP item 14) claim C17 over `|A| ≥ 2`.
   - Revisit when: the owner changes the actor model.
22. **Access structure in the charter.** The charter fixes, at birth, a monotone access structure over the shards, always ANDed with Fenrir. Building blocks: AND of shards (additive), threshold `k`-of-`m` among a group of actors (the group's shard is Shamir-shared among its members, and each member's contribution is weighted by its Lagrange coefficient for the chosen subset), OR (escrow of one shard to another holder, as the P2 guardian escrow). P2's seizure path is `Fenrir AND (user OR G)` with `G` a 3-of-5 group.
   - Drivers: owner ruling 2026-11-14 on arbitrary actors; R1 with several actors; C17.
   - Considered options: the entry records no alternative. It lists the building blocks of the structure.
   - Outcome and authority: the entry text, owner ruling 2026-11-14 as folded by the lead. Entry 43 supersedes its ECDSA reading that one slot serves every signing set.
   - Consequences: Lagrange weights per signing set; escrow certificates at birth for OR gates; P2 seizure is `Fenrir AND (user OR G)`.
   - Confirmation: conformance, Lean oracle (LOOP item 13) computes weights and refuses signing sets outside `Γ` (SH-001 to SH-004, SH-022); outcome, Quint model (LOOP item 14) claim C17.
   - Revisit when: a gate type beyond AND, threshold and OR is needed.
23. **Fixing the signer set before the challenge.** For Schnorr and Ed25519 the challenge depends on the aggregate nonce, so the contributing subset and every contributor's nonce must be fixed before anyone computes a half-signature. Each actor publishes a pool of two-nonce commitments `(D_j, E_j)` on the board (as the committee does). The initiator's envelope names the subset, the actors' slots and the fee grid; FROST-style binding factors `ρ_j = H(j, message, all commitments)` fix `R`. Each named actor reads the request (actors are parties and may see what they co-sign; blindness is toward Fenrir operators) and posts its sealed contribution before expiry. If an actor fails to respond, the initiator issues a new generation with another subset. An actor never uses one slot for two messages; its software keeps that state.
24. **ECDSA with many actors.** The multiplicative structure needs a joint presignature session among Fenrir and every actor of the access structure at birth (or per slot refill). State its cost and the open instantiation.
25. **Blindness.** Envelope contents are hidden from Fenrir operators exactly as before. Each actor sees the request it co-signs. Actor identities are hidden from operators where the access structure allows it (contributions are sealed capsules inside the envelope).

## Speed (lanes speed/{fable,astra,carbon}/SPEED.md, 2026-11-14)

All three lanes find the same bottleneck: the committee's Schnorr slot pool, about 110 ms per node per K = 8, L = 2 spend unbatched, against about 12 ms on the request path. Latency is five serial board commits after Midnight finality.

26. **Arithmetic (all three, no new proof).** Evaluate Feldman commitments by Horner with the node index as a small integer (addition chains), use the fixed-base generator table, check torsion once per decoded point and hash wire bytes instead of re-encoding, reduce 512-bit hashes in one wide reduction, batch affine conversions with one inversion, verify batches by a random linear combination with 128-bit coefficients and a per-polynomial fallback that names the bad dealing, and run the combiner optimistically (check partials only when the combined signature fails). The prototype defects at `impl/src/algebra.rs:140-147`, `impl/src/algebra.rs:10`, `impl/src/ed25519.rs:37-53,423-430,512,589` and `impl/src/signing.rs:78-81,160` are fixed in the discovery prototype (PLAN item 13).
27. **Slot pool.** Per-node slot commitments are evaluated lazily and cached; a dealer's batch of slot dealings is checked with one equation (Carbon, Astra, Fable). A committee slot serves one (generation, input) pair, not one variant (Fable): the committee releases one partial per slot, for the one variant that is broadcast, so `K` variants on one slot never yield two committee partials. `G_max = 2` generations per request is a protocol constant; a second fee bump is a new request. C12's counting is restated around the anchor (proof obligation). ECDSA keeps `K·L` slots: two user halves on one ECDSA slot reveal the user's slot secrets.
   - Drivers: slot-pool cost (about 110 ms per node per spend, speed lanes); C3, C12; ROS.
   - Considered options: (a) one committee slot per (variant, input); (b) one committee slot per (generation, input) with one partial per slot; (c) one committee nonce per slot for all variants without the one-partial rule (rejected: ROS).
   - Outcome and authority: (b) with `G_max = 2`, lead decision on the speed lanes, 2026-11-14. ECDSA keeps `K·L` slots.
   - Consequences: a Schnorr header names `G·L` committee slots; C12's counting is restated around the anchor (O27); a second fee bump is a new request.
   - Confirmation: conformance, Lean oracle (LOOP item 13) checks the slot count and one partial per slot (EN-010, SL-027); outcome, Quint model (LOOP item 14) invariant C12.
   - Revisit when: O27 is proved or refuted.
28. **One polynomial per envelope (Fable).** The data key `κ_0` stays the only dealt secret. Header and variant keys are threshold-PRF outputs `κ_0·H_c(dd ‖ label)` (the construction already used in §7.4). The 16 inner dealings go; an outside actor deals nothing. Theorem D is restated and C8, C9 rest on DDH (proof obligation). Reason: it removes 40% of request-path CPU and lets `n = 17` keep the full fee grid in 16 KiB.
   - Drivers: request-path CPU (40% from inner dealings) and the 16 KiB frame at `n = 17`; C8, C9.
   - Considered options: (a) 16 inner dealings, one per key; (b) one outer dealing of `κ_0` and threshold-PRF keys `κ_0·H_c(dd ‖ label)` (Fable).
   - Outcome and authority: (b), lead decision on the speed lanes, 2026-11-14.
   - Consequences: C8 and C9 rest on DDH (O26); an outside actor deals nothing; nobody reconstructs `κ_0`.
   - Confirmation: conformance, Lean oracle (LOOP item 13) derives header and body keys from labels (EN-016); outcome, Quint model (LOOP item 14) invariant C9 (one label per release).
   - Revisit when: O26 is settled or a key needs a second dealing.
29. **Latency.** The wallet posts the envelope while `authorize` finalizes (all three); nodes release only after both the QC and finality. ACK merges with share release, and OPENED with ADMIT and OBS, which needs the SCHEME §3.6 rule change "OBS is posted with ADMIT" (Fable, Carbon); the normal path is two board commits after finality. The TEE peer witness rides on board votes with one group-committed flush per block (Carbon). Board-first authorization (no Midnight wait) is an option for P0 and for P1 charters with stateless predicates only; it is forbidden for P2 and for cumulative limits or vetoes (Fable).
   - Drivers: latency (five serial board commits after Midnight finality); C6, C7, C8.
   - Considered options: (a) post after finality; (b) post while `authorize` finalizes, release after QC and finality, merge ACK with release and OPENED with ADMIT and OBS; (c) board-first authorization for every profile (rejected: C7).
   - Outcome and authority: (b) with board-first limited to P0 and stateless P1, lead decision on the speed lanes, 2026-11-14.
   - Consequences: the normal path is two board commits after finality; board-first is forbidden for P2 and for cumulative limits and vetoes; entry 35 keeps OPENED separate for collecting requests.
   - Confirmation: conformance, Lean oracle (LOOP item 13) refuses release before QC and finality and refuses board-first records for P2 (RQ-030, AU-011); outcome, Quint model (LOOP item 14) invariants C6 and C7.
   - Revisit when: Midnight finality time changes materially or O29 is proved.
30. **Ticket proof: reverses item 9 (Fable, Carbon; Astra dissents).** The ticket commits `x(R)`, so the proof contains no curve arithmetic. One midnight-zk PLONK circuit at `k = 18` proves the sighash relation with the library's own SHA-256, SHA-512 and Keccak gadgets, sharing sighash prefixes and midstates. No STARK and no BLS12-381 wrap. Reason: midnight-zk has no STARK verifier gadget, the wrap (2^20) is larger than the statement it wraps (2^18), and the single circuit fits the k ≤ 21 rule with room. Astra's alternative (KoalaBear STARK, aggregation, one wrap) stays the fallback if Compact cannot call the hash gadgets; that is new open item O25. Poseidon2 is used only for protocol-internal hashes; host-chain sighashes stay SHA-256, SHA-512 or Keccak.
31. **Quorum certificate.** Batched Ed25519 signatures, not BLS aggregation (Fable over Carbon): a pairing check costs about 1.3 ms, twelve Ed25519 verifications about 0.4 ms, less batched. Aggregation pays at hundreds of signers.
32. **Deferred, each needs a proof first:** Carbon's seeded shares (`f + 1` ciphertexts, shares of `t − 1` nodes defined as the pads) and Fable's derived slot shares, because both touch the public complaint and Theorem E's related-dealing defence; Vandermonde extraction of slots waits on O6.

**Rejected (union of the lanes' "what not to do"):** one user or actor nonce across variants (breaks C3); shared ECDSA slots (C3); returning named but unused slots to the pool (C12); one committee nonce per slot (ROS); any share or partial before the QC (C8); release at Midnight inclusion before finality (C6); board-first for P2 or stateful predicates (C7); skipping the witness on an optimistic path (rollback); short batch coefficients or no fallback; variable-time arithmetic on secrets (TEE timing); replicated PRSS for nonces (no commitments, C(n, t−1) keys); an anchor output for fee bumps (B5); a second frame class (O7); GPUs on nodes.

**Cost after 26–31 (estimates, to be measured under `heavy-slot --exclusive` in `impl/benches`, PLAN item 13):** request-path CPU 1.8–2.7 ms per node; slot replenishment 1.2–3.6 ms per spend; one core serves about 160–400 requests per second at `n = 9` and 95–260 at `n = 17` (Fable's calibrated range; Carbon's 730 and 395 assume EPYC and every batch win). Latency `F_M` + about 2 board commits.

## Folding 26–32 into DESIGN.md: conflicts with the multi-shard text (2026-11-14)

Items 26–32 were written for the single-user form. Each entry below resolves a point where they meet the multi-shard design (items 21–25) or leave a rule unstated. Every resolution keeps the security claim of DESIGN.md §9 that was at stake.

33. **Actor capsules carry the header key and the capsule keys, never `κ_0`.** Item 28 makes every key a PRF output of `κ_0`. An actor that held `κ_0`, as the multi-shard actor capsule did, would derive every variant body key and read the initiator's scalars and the other actors' contributions for unselected variants, which breaks C9 and the secrecy part of C18. The capsule now holds `k_hdr`, the position, the token and the `K` random capsule keys `ck_v`. Its size is unchanged (`97 + 32·K`).
34. **"An outside actor deals nothing" means no contribution dealing.** An actor seals its scalars to the variant keys `P_{v,g} = y_{v,g}·G` in the header (Fable §3.7(a)). A contribution frame still carries the one outer dealing every envelope has, because a frame without a dealing and its proof `π` is distinguishable before ordering, which breaks C21 and the B5 grade of item 25. An embedded contribution has no frame and no dealing. Cost of the choice: about 0.8 ms per node per contribution frame, against 0.06 ms for an embedded one.
   - Drivers: C21 (one public shape before ordering), B5 grade of entry 25; entry 28 ("an outside actor deals nothing").
   - Considered options: (a) a contribution frame without a dealing; (b) a contribution frame with the one outer dealing every envelope has, sealed contributions to `P_{v,g}`.
   - Outcome and authority: (b), lead decision folding 26 to 32 into the multi-shard design, 2026-11-14.
   - Consequences: about 0.8 ms per node per contribution frame against 0.06 ms for an embedded contribution.
   - Confirmation: conformance, Lean oracle (LOOP item 13) applies the same public checks to contribution frames (EN-018, EN-022); outcome, Quint model (LOOP item 14) treats frames as one message class before ordering.
   - Revisit when: a second frame class is adopted (O7).
35. **A collecting request keeps a separate OPENED vote.** Item 29 merges OPENED with ADMIT. A request with empty actor slots cannot be admitted in the vote that opens it, and it must hold its slots before its actors answer (C20). Its nodes vote OPENED once the authorization is in force, which reserves the slots; ADMIT with OBS follows collection. The two-commit path applies to requests with no collection: the single-user form and requests whose contributions are all embedded. Slots are reserved by the first `q` votes with one header hash while the authorization is in force, and named slots that no request reserved stay in the pool.
   - Drivers: C20 (slots held before actors answer); entry 29's OPENED and ADMIT merge.
   - Considered options: (a) merge OPENED with ADMIT for every request; (b) keep OPENED separate for collecting requests, reserving slots on `q` votes with one header hash while the authorization is in force.
   - Outcome and authority: (b), lead decision folding 26 to 32 into the multi-shard design, 2026-11-14.
   - Consequences: the two-commit path applies only to requests without collection; named slots that no request reserved stay in the pool.
   - Confirmation: conformance, Lean oracle (LOOP item 13) reserves slots at OPENED and admits after collection (RQ-016 to RQ-018, SL-008); outcome, Quint model (LOOP item 14) invariant C20.
   - Revisit when: contributions can be checked before ADMIT.
36. **An actor burns one pool pair per half, not per `(variant, input)`.** Item 27 puts several variants on one committee slot, and the Rejected list forbids one actor nonce across variants. A named actor therefore uses `H = L·Σ_v min(v, G_max)` pairs per request, 30 at `K = 8`, `L = 2` (was 16). `N_pool = 64` stays; an actor refills below `H` unused pairs. ECDSA keeps `K·L` halves.
   - Drivers: C3 (no actor nonce across variants); entry 27's several variants per committee slot.
   - Considered options: (a) one actor pair per (variant, input); (b) one actor pair per half, `H = L·Σ_v min(v, G_max)` pairs per request.
   - Outcome and authority: (b), lead decision folding 26 to 32 into the multi-shard design, 2026-11-14.
   - Consequences: 30 pairs per request at `K = 8`, `L = 2`; `N_pool = 64` stays; refill below `H` unused pairs.
   - Confirmation: conformance, Lean oracle (LOOP item 13) refuses a request that names one pair for two halves (SH-014, SH-022); outcome, Quint model (LOOP item 14) invariant C3.
   - Revisit when: a single binding factor for actors is adopted (O6, O20).
37. **Contributions are checked at release, in both modes.** With scalars sealed to `P_{v,g}` no node can check a contribution before its variant is released, so the TEE-mode check before ADMIT is gone and a bad contribution costs a reissue in either mode. O21 is widened from non-TEE mode to both. The header carries no contribution points `S = s·G`: the combiner checks each scalar against its equation directly, and only when the combined signature fails. This departs from Fable §3.2, which kept the points; they served no check once every check runs on the opened scalar, and they cost 1 KB of frame.
38. **The release witness is sent after the anchor, not on the ADMIT vote.** Item 29 puts the TEE witness on board votes. The digest of a release entry is `(j_g, H(tickets))`, and `j_1` is fixed only by the OBS reports of the committed ADMIT block, so a node cannot attach that entry to its own ADMIT vote. `open` entries ride on the vote for the ordering block; `release` and `slot` entries go in one batched message per peer and board height right after the anchor; peers flush once per height in both cases. The entry digests are unchanged, so the bound of §7.7 needs no new proof. Fable's merge of the open and release witness is not taken: it changes the digest and needs a proof.
   - Drivers: the rollback bound of §7.7; `j_1` is fixed only by the OBS reports of the committed ADMIT block.
   - Considered options: (a) witness on the ADMIT vote (entry 29); (b) `open` entries on the ordering vote, `release` and `slot` entries in one batched message per peer and height after the anchor; (c) merge open and release witness (Fable; changes the digest).
   - Outcome and authority: (b), lead decision folding 26 to 32 into the multi-shard design, 2026-11-14.
   - Consequences: entry digests and the §7.7 bound are unchanged; peers flush once per height.
   - Confirmation: conformance, Lean oracle (LOOP item 13) emits release only after the anchor and the witness (RQ-035); outcome, Quint model (LOOP item 14) rollback adversary finds no second release digest.
   - Revisit when: a proof covers a merged witness digest.
39. **Two rules of the lane mechanisms that the cost figure of items 26–31 assumes are now stated in the design.** Lazy checks: a check that concerns one variant runs when that variant is released, and the comparison of the ticket's `x(R)` with the node's own `R` is a precondition of release (Fable §3.5). Board votes: a node signs once per block, the vote lists its posts, complaints and VOID posts stay individually signed, and peer-channel messages carry no signature (Fable §3.6). Not taken from the lanes, because no item adopts them: the single binding factor for actors (it changes O6 and O20), ristretto255 for suite 3, and the ECDSA birth changes.
40. **C18's secrecy needs an honest initiator.** An actor cannot check that `P_{v,g}` is the PRF key of its label without `κ_0`. A dishonest initiator that substitutes its own key reads its actors' scalars. It gains no signature, the adversary of C17 holds those scalars in any case, and the combiner's check `y_{v,g}·G = P_{v,g}` ends the request VOID. The limit is stated in §6.4 and C18.
   - Drivers: C18 secrecy; an actor cannot check `P_{v,g}` without `κ_0`.
   - Considered options: the entry records no alternative. It states a limit of entries 28 and 34.
   - Outcome and authority: the entry text, lead decision folding 26 to 32 into the multi-shard design, 2026-11-14.
   - Consequences: a dishonest initiator reads its actors' scalars and gains no signature; the combiner check `y_{v,g}·G = P_{v,g}` ends the request VOID.
   - Confirmation: conformance, Lean oracle (LOOP item 13) voids a request whose `P_{v,g}` fails the combiner check (RQ-038); outcome, Quint model (LOOP item 14) claim C18 stated with the honest-initiator premise.
   - Revisit when: an actor can check `P_{v,g}` without `κ_0`.
41. **Status changes in §9, and new open items.** C8 goes from proved to sketched and C9, C18 secrecy from information-theoretic to computational (O26, Theorem D restated). C12 goes from proved by counting to sketched (O27). C13's merged step is O28. C6 and C11 for board-first are O29. O25 is the Compact access to the hash gadgets, with the STARK path as fallback. O30 holds the deferred items of 32. O31 is the measurement of §11. O4, O6, O16, O18, O20 and O21 are restated.

## Cross-family review 3 (review-3/TRIAGE.md)

Entries 42 to 46 carry the MADR fields of the Architecture and Technical Decisions profile. Authority for each: the loop lead, under the owner's standing order to decide review findings with reasons (LOOP.md rules).

42. **Nonce agreement rests on board safety; `slot_anchor` for `|C| < t`.**
   - Context and problem: honest nodes agree on the one ticket of a committee slot because they read one board. C5, C9, C12 and C20 claimed `|C| < t`. A coalition of `f < |C| < t` non-TEE nodes can certify conflicting board histories, give honest nodes different requests or anchors on one slot, and solve three equations `σ_b·s_f^{(b)} = d_ℓ + ρ_b·e_ℓ + σ_b·c̃_b·x_f` for `x_f` (review-3 A-F1). The flaw predates item 27: cross-request slot uniqueness was always a board rule.
   - Drivers: R2 (nobody holds `x`), C5, C12; the hard rule that `t = n − f`.
   - Considered options: (a) state the adversary of the slot rules as `|C| ≤ f` in non-TEE mode; (b) raise a release quorum so two quorums meet in an honest node at `|C| < t`, which needs `q' ≥ (n + t)/2 = 8` against liveness `q' ≤ n − f = 7`, impossible at launch; (c) append the slot-to-ticket entry to the seat log and release only after a Midnight checkpoint root covers it (`slot_anchor`), which restores `|C| < t` at one checkpoint interval plus Midnight finality per generation and no Midnight transaction of its own; (d) withdraw slot sharing, which does not help, because forks also give two requests one slot.
   - Outcome: (a) as the default, stated in §4.1, C5, C9, C12, C20 and R2; (c) as a committee-wide option, open item O32. A per-charter option would not help, because `x_f` is shared by every address. TEE mode keeps `|C| < t` while the enclaves hold and at most `n − 1 − 2f` operators roll back or clone (§7.7), because enclaves sign board votes and never sign two blocks at one height.
   - Consequences: the non-TEE committee half resists more than `f` corrupt nodes only with `slot_anchor`. O6 and O27 state their oracles under board safety.
   - Confirmation: outcome, model check: item 26 Quint model with a forking board adversary of `f + 1` to `t − 1` nodes shows two tickets on one slot without `slot_anchor` and none with it (review-3/QUINT-ITEMS.md Q1); O32 proof.
   - Revisit when: O32 is measured, or the board gains a safety argument beyond `f`.

43. **An ECDSA slot is bound to one leaf set.**
   - Context and problem: §3.6 step 7 let one ECDSA slot serve every signing set of a threshold group. With every node and one group member corrupt, requests with subsets `{A, B}` on `h_1` and `{A, C}` on `h_2` on one slot give two evaluations of the group's half line; each honest member answers once, yet `w_γ`, `μ_γ` and then `x` follow (review-3 A-F2). The same holds for the primary and escrow branches of an OR gate on one reserved slot.
   - Drivers: C12, C17, R1 with several actors.
   - Considered options: (a) bind each slot at birth to one leaf set `T_ℓ`, enforced by the members; (b) a Midnight slot nullifier checked by the members before they answer, which keeps flexibility but adds a Midnight record per ECDSA slot and a shared secret per slot; (c) rely on the board, which fails against a fully corrupt committee.
   - Outcome: (a). Members enforce it locally, so it holds against all `n`. A G-reserved slot is never the user's.
   - Consequences: `N_slot` is spread over leaf sets; a silent member makes only its own leaf sets' slots unusable; a refill session targets one leaf set. Supersedes the "one slot serves every signing set" sentence of item 22's ECDSA reading and item 24.
   - Confirmation: conformance, test vector `vectors/check.py` part (d) shows the recovery on a shared slot and the refusal under binding; outcome, Quint item Q2; O33.
   - Revisit when: a many-party ECDSA instantiation (O19) offers per-signing-set slots at lower cost.

44. **Slot precedence by board order.**
   - Context and problem: item 35 reserved a slot for the first request whose `q` votes land while its authorization is in force. A non-TEE node reads a header after ordering, before its authorization is final, and can copy its slots into a request whose authorization comes into force first, so the first request ends VOID, against C13.
   - Drivers: C13, C20.
   - Considered options: (a) precedence by board order, lapsing at ordering height plus `Δ_c` if not in force; (b) keep item 35 and state the griefing in C13; (c) hide slot ids from nodes until the authorization is in force, which breaks the release checks.
   - Outcome: (a). A header names exactly `G·L` slots, so an envelope that never comes into force burns at most that many. Named slots of a lapsed or ended request are burned, even when never reserved: a slot whose id a header showed is never dealt again. An envelope with no authorization can therefore burn `G·L` slots per ordered frame; that pool cost is part of O34.
   - Consequences: item 35's "named slots that no request reserved stay in the pool" no longer holds: a named slot is burned. An honest collision ends the later request VOID with SLOT_TAKEN, and C13 says so.
   - Confirmation: outcome, Quint item Q4 (no later-ordered request takes a slot of an earlier live one).
   - Revisit when: slot spam by envelopes that never come into force is measured as a pool cost.

45. **Sealed contributions use the outer-dealing digest `dd` as context, and `dd` is unique per epoch.**
   - Context and problem: an embedded contribution was keyed with `hd`, but `hd` covers `body_0`, which holds that ciphertext: a fixed-point problem with no construction (review-3 A-F7). Separately, a dealer could put one outer dealing under two sets of bodies; both share every PRF key.
   - Drivers: C9, C18, C21, the two-commit path of item 35.
   - Considered options: (a) `dd` as context plus a node rule refusing a repeated `dd`; (b) a new contribution-context digest over the immutable header fields; (c) drop embedding.
   - Outcome: (a). `dd` is fixed before any body exists and already binds the PRF keys.
   - Consequences: nodes keep the set of `dd` values of the epoch. Amends item 34's sealing formula.
   - Confirmation: conformance, vectors seal and open under `dd`; outcome, Quint item Q6 (no two ordered envelopes share `dd`).
   - Revisit when: the second size class (O7) or a new frame type changes the outer dealing.

46. **Corrections that keep every decision, with their reasons.**
   - Context and problem: review 3 found an unspecified proof transcript, missing envelope fields, a cold-start window, a witness liveness gap, an offline birth gap and claims stated beyond their adversary.
   - Drivers: C8 to C10, C12, C13, C16, C21, B6, R3.
   - Considered options: fix in place or record as open items; each fix below is a single rule or a status change, so fixed in place.
   - Outcome: (1) the Chaum-Pedersen challenge hashes the whole statement including `Y_{i,lab}`; a challenge without it admits a forged partial that blames an honest dealer (A-F3). (2) Theorem D restated claims pseudorandomness of `Z_lab` and `KDF(Z_lab)`, and for `y` only security of the encryption to the published `P` (A-F4). (3) A cold start through `E` without a verifiable board record of the window burns every ECDSA slot unclaimed at the checkpoint, the reservation window of the Sessions rule; the same rule covers cold-start path 1 and the recovery transition of §5.8 (A-F5, B-F11). (4) Capsules carry `R_0` per half, a salt seed per variant, the initiator term `T_0` and the signing set; frame capacities drop by one actor (A-F6). (5) An `open` witness entry is provisional until its block has a QC (A-F8). (6) C10 is narrowed to nodes that cannot enumerate the candidate `(x(Q), m)` (A-F9). (7) C8, C9, C10, C21 hold below `t` nodes or broken enclaves; §9.2 drops C8 and C12 from the kept columns (A-F10). (8) B6 is PARTIAL: the mempool sees a broadcast transaction (A-F11). (9) A network-created shard is proved by `pop_U` at registration plus a proof of `δ` at birth, which links one holder's addresses in non-TEE mode (A-F12).
   - Consequences: §11 sizes and §4.6 capacities restated from `vectors/sizes.py`; new limits §6.4 items 12 to 14; C15 and C16 conditional on O5, O10, O17.
   - Confirmation: conformance, `vectors/check.py` forged-partial case; outcome, Quint items Q3 and Q5.
   - Revisit when: O26, O28 or O8 is written.

47. **A request with a release never settles to unspent.**
   - Context and problem: a VOID or EXPIRED request returned its record to unspent with a fresh nullifier, even after a release. An initiator with a short `exp` keeps a signed transaction, lets the request expire, and broadcasts it later past a hold or a cumulative limit. A share complaint ordered after ADMIT could also void a request whose partials had left (review-3 B-F14).
   - Drivers: C6, C7, C11, R4.
   - Considered options: (a) settle a released request as RELEASED, locked to its pinned input, and let a later authorization spend only that input; (b) a minimum `exp` past host confirmation, which no bound makes safe on Bitcoin; (c) a complaint window before ADMIT, which costs a commit on every request.
   - Outcome: (a), and a share complaint after the first ADMIT vote records the dealer's fault and voids nothing.
   - Consequences: a record with an unconfirmed release stays locked until the pinned input is spent. P2 holds and seizures spend the same input.
   - Confirmation: outcome, Quint item Q9.
   - Revisit when: a host chain without a pinned input or nonce is added.

48. **ECDSA tickets are bound to the record's slots; guardian slots are separate.**
   - Context and problem: an Ethereum message hash does not contain the sender, and the ticket `(ℓ, h)` named any slot. An owner could authorize on an unheld record and name a slot of a held record (B-F4). The owner could also burn the `G_g` slots reserved for guardians, and `G_g = 4` was below one P2WPKH seizure of `K·L = 6` (B-F5).
   - Drivers: C6, C7, R4, P2 seizure on ECDSA chains.
   - Considered options: (a) slot roots `slr_own`, `slr_G` committed in the asset record, certified by `q` nodes, and proved in `authorize` per source; (b) TEE-only check of the slot's `X`, which leaves non-TEE mode open.
   - Outcome: (a) in both modes, plus the TEE check of the slot's `X`. `G_g = 2·K·L_max`.
   - Consequences: the `authorize` circuit proves membership for ECDSA tickets (part of O4 and O22). Refill sessions update the root on Midnight.
   - Confirmation: outcome, Quint item Q8.
   - Revisit when: O19 changes the slot model.

49. **The envelope id covers `auth_ref`; the header carries `ic` and `r_tkc`; FINAL uses its own key.**
   - Context and problem: `auth_ref` sat outside `hd` and `π`, so anyone could rewrite it and order a copy under the same `hd` (B-F2). No node could check `auth` against `hd` and `tkc`, because the header lacked `ic` and `r_tkc` (B-F3). `Enc_{k_hdr}(txid)` reused the header key (B-F6).
   - Drivers: C6, C13, C10.
   - Considered options: bind `auth_ref` into `π` through `eid = H(hd ‖ auth_ref)`, or put `auth_ref` inside `hd`, which is circular because `auth` commits to `hd`. For `ic` and `r_tkc`, carry them in the header (64 bytes) or prove the opening on Midnight, which needs nodes to read a proof anyway.
   - Outcome: `eid = H(hd ‖ auth_ref)` as the context of `π`; random `auth_ref` when unused; `ic` and `r_tkc` in the header; `k_fin = KDF(Z_hdr ‖ "final")`; every AEAD key encrypts one message under a zero nonce.
   - Consequences: the header grows by 64 bytes; frame capacities in §4.6 and §11.1 restated from `vectors/sizes.py`.
   - Confirmation: conformance, `vectors/sizes.py`; outcome, Quint item Q10 (a rewritten `auth_ref` is never ordered).
   - Revisit when: the frame format changes.

50. **Further corrections from review 3 that keep every decision.**
   - Context and problem: the second review found gaps in failure handling, binding factors, witness keys, board-first relay, hold timing, blindness statements, rotation and claim status.
   - Drivers: C2, C5 to C7, C10, C13, C14, C21, B1, B5, R4.
   - Considered options: fix in place, or record as open items; the single-rule fixes are made in place, the larger ones are open items O34 and O35.
   - Outcome: (1) one honest combiner sends `Z_{j_g,g}` with the proved partials so every node can post a verified VOID, and ECDSA slot records hold escrow commitments by leaf id (B-F8). (2) Binding factors and `CL` use the leaf id, and `cm_addr` binds `chain_id` and the Taproot root (B-F9). (3) ECDSA actor table bytes counted in `sizes.py` (B-F10). (4) Witness `slot` keys carry suite and epoch, or the ECDSA slot record (B-F13). (5) Board-first: `nf` enters the pending set only after the proof verifies, the root-age check keeps a relay margin, and the pending set is checkpointed (B-F15; O29 stays open). (6) STALLED is a board predicate at height `exp_c`, and a complained contribution frame is detached (B-F16). (7) The hold check compares Midnight heights only, and P2 waits `Δ_hold` Midnight blocks before generation 1 (B-F17). (8) BIRTH_OK goes to the coordinator, not the board, and vote kinds are a stated limit (B-F18). (9) The ECDSA slot session runs in the clear in both modes: stated, B1 for ECDSA is PARTIAL in TEE mode, and encryption is O35 (B-F19). (10) The TEE claims carry the rollback bound `n − 1 − 2f`, and `slot_anchor` (O32) is the committee-wide remedy, because `x_f` is shared by every charter (B-F20). (11) C1 and C2 need fewer than `q` broken enclaves (B-F21). (12) O5 states that the complaint window of §8.1 needs synchrony (B-F22). (13) C2, C5, C6, C7 name their missing obligations (B-F23).
   - Consequences: P2 generation 1 waits `Δ_hold` blocks; slot pool sizing is O34.
   - Confirmation: outcome, Quint items Q11 to Q13.
   - Revisit when: O29, O32, O34 or O35 is closed.

## seald Sessions (Veritee branch `committee-sessions-seald`, `openspec/changes/add-seald-sessions/`)

Entry 51 carries the MADR fields. The Veritee decision records are at `specs/refinement/decisions/D-NNN.md` on branch `committee-sessions-seald` of the Veritee repository, which continues branch `committee-sessions`. Entry 69 takes the records D-032 to D-045. D-001 to D-025 and D-031 are owner decisions of 2026-11-14. D-026 to D-030 are lead decisions under the owner's AFK delegation that wait for owner confirmation. The batched bind and the seat log of choices 3 and 11 follow the owner ruling of 2026-11-14 on Midnight writes. The lead decides the other choices of this entry that no D record covers, under the owner's standing order to decide with reasons.

51. **Split-line dealing state is session-sealed and witness-fenced.**
   - Context and problem: DESIGN kept nonce slot shares, ECDSA slot shares and request state in RAM only. Their durability came from peer repair and from `E`. A whole-committee restart voided every pending Schnorr request and needed `E` for every ECDSA slot. Veritee seald Sessions give each seat durable state under a key that `t` peer enclaves derive, fenced by the peer witness, with burn rules for a restart from rolled-back disks. The mapping must keep C12 and C16 under rollback, keep slot ids from showing an account, and close the recovery gap Q-009 of the Sessions architecture: after a rollback of every disk, an ECDSA slot claimed after the latest Midnight checkpoint looks unused.
   - Drivers: C5, C10, C12, C13, C15, C16; the owner's rule of no per-event Midnight writes; Sessions goals G1 to G4; SS-050 to SS-073, SS-102, SS-104, SS-112 to SS-135; review finding B-F3 (Sessions review: a seat with a lost tier 0 is forgetful and counts in `c`).
   - Considered options:
     - (a) Keep RAM only and rely on `E` at every whole-committee restart.
     - (b) Map each class of state onto a seat-bound session, with the Sessions burn rules, as below.
     - (c) Make sessions portable between seats. D-001 rejects it: two shares in one enclave weaken the threshold.
     - For the recovery gap: (r1) `E` reshares the ECDSA slots unclaimed on a board record with valid QCs; (r2) `E` burns every slot above a floor and reshares under new indices; (r3) `E` reshares an ECDSA slot only when Midnight shows that no seat bound it, which needs seald's slot anchors, and otherwise reshares none.
   - Outcome: (b) and (r3). The binding choices:
     1. **Where state lives.** `σ_i` stays in tier 0 under `K_tpm` (D-004: SS-074 to SS-077, SS-079, SS-097). The shares of `x_f` and the private epoch keys live in session `keys`. The committee slots of an epoch live in the sequential pool `slots-e`. The ECDSA committee slot shares of one address live in an account pool named by a random id, so a record header shows no account. Request state lives in session `requests` as a cache that the node checks against the board. Shares of `κ_0` are not sealed: the board holds their dealing. Sessions are bound to one seat, and the session key comes from the threshold PRF only (D-001: SS-006, SS-007, SS-012, SS-014, SS-017. D-003: SS-007, SS-009, SS-011, SS-110). DESIGN §2.2, §3.6, §4.1, §7.4. Claims C12, C16.
     2. **One committee pool per suite and epoch.** One shared index space would let the floor pass over the unreserved slots of the less used suite, and those slots would be lost. The checkpoint therefore shows the suite of each pool. The witness `slot` key is `(node, purpose, ℓ)`, with the purpose naming suite and epoch, which keeps the content of entry 50 item (4) (SS-050). DESIGN §4.1, §7.7, §6.4 item 16. Claim C10.
     3. **Slot states and the bind.** A slot is `free`, `bound(H(tk))` or `burned`, and only moves forward. Binding gets `w` acks for the `slot` entries, then seals the `bound` state, before any partial leaves. A node binds every slot of one pool session that one board height anchors in one batch, so a release waits for two bind rounds whatever the number of slots (owner ruling 2026-11-14: use the batched design). seald binds a batch of slots in one call (SS-140, SS-141), and its cost is O36. A restored `bound` slot releases only for the same ticket. `slot_burn` at FINAL, VOID or EXPIRED is the erasure (SS-050 to SS-062, SS-118). DESIGN §4.5 items 4 to 6, §5.11, §7.6 to §7.8. Claims C5, C12.
     4. **Reservation window at the vote.** Indices are reserved in increasing order. A header names only indices in `(h, h + B]` of the latest checkpoint or pending indices of its own request. Honest nodes vote under this rule, and seald enforces it again at `slot_bind`. A skipped index is lost (D-006: SS-063 to SS-066. D-011: SS-063, SS-064. D-009: SS-004, SS-088. D-030: SS-004, SS-063, SS-067). This makes DESIGN §4.1 consistent with SS-064 and answers Sessions open question Q-001. A header with an index at or below `h` that is not pending ends VOID with SLOT_TAKEN. DESIGN §2.3, §4.1. Claims C12, C13.
     5. **Whole-committee restart.** The node classifies from one verified ledger snapshot: fewer than `w + 1` continuous seats (D-005: SS-067, SS-098, SS-106). Boot counters come only from signed `RestoreDone` (D-014: SS-112, SS-117). The restart burns the window `(h, h + B]` and the pending slots of each checkpoint read, and the requests that hold them end VOID (D-002: SS-063, SS-064, SS-067, SS-068, SS-104, SS-113, SS-114. D-031: SS-067, SS-068, SS-104). Running nodes burn too (D-021: SS-113, SS-120). The contract enforces the checkpoint rules (D-013: SS-103, SS-104, SS-117, with the root chain of SS-072, SS-119 and SS-136). DESIGN §7.11, §7.13, §14.3. Claim C16.
     6. **Account pools.** Every `free` and `bound` account-pool slot burns once per whole-committee restart (D-018: SS-004, SS-063, SS-065, SS-114). The restart marker `restart_seq` and each session's `restart_mark` carry that burn to nodes that boot later (D-024: SS-002, SS-005, SS-008, SS-069, SS-112, SS-120 to SS-125). A restart generation ends at a checkpoint with the marker and `w + 1` continuous seats (D-028: SS-113, SS-133). A put entry in the seat log, once a checkpoint root covers it, stops a second put of one share, and the first covered entry of a share counts (D-027: SS-128 to SS-131, SS-136 to SS-138, SS-089, SS-090). DESIGN §3.6, §4.5 item 7, §7.4, §7.11, §7.13. Claims C12, C16.
     7. **The count `c` of the witness bound.** A seat with a lost tier 0 counts among the `c` colluders until its fetch from `w + 1` peers completes. A rolled-back seat counts for a session until a later version commits (D-025: SS-102, SS-126, SS-127. D-026: SS-102, SS-016. D-012: SS-102). This closes review finding B-F3. DESIGN §7.4, §7.7. Claims C5, C12.
     8. **Recovery reshare of ECDSA slots (r3).** A reshare gives new share bytes with the same nonce `R_ℓ`, so the put entry (SS-128 to SS-131, SS-137, SS-138) and a new index both fail to stop a second use. A board record with valid QCs can be a truncated prefix, so (r1) fails after a rollback of every disk. (r2) has no referent: account pools have no floor on Midnight. Under (r3) `E` holds ECDSA shares only on a committee with seald's `slot_anchor` on, keeps the slot key of each seat and the slot-nullifier key `k_nf` with them, reads each seat log up to the root of the latest checkpoint, and reshares a slot that no covered binding names. A log that `E` cannot read in full counts as binding every slot of its seat. Without anchors every ECDSA address refills by a new session. No per-slot Midnight record is needed (SS-070 to SS-073, SS-092, SS-119, SS-139; root chain SS-072, SS-136). DESIGN §2.2, §3.9, §5.8, §7.11. Claims C15, C16.
     9. **Body and size.** The session body has one canonical encoding, and `S_max` limits its accounted size (D-029: SS-134, SS-135, SS-088). DESIGN §2.3.
     10. **seald rules that DESIGN takes as they stand.** Epoch close waits for every session of any seat in that epoch (D-023: SS-078 to SS-080), DESIGN §7.8. Peers check the app image before a session partial (D-019: SS-110), and version reports carry the seat's signed statement (D-017: SS-111), DESIGN §7.4. Session operations run one at a time (D-020: SS-107, SS-023), DESIGN §7.7. Restore authenticates first and seals a new version, and a split version restores by plurality (D-015: SS-030, SS-031, SS-033 to SS-036. D-016: SS-031, SS-032). `session_close` discards changes without a checkpoint (D-007: SS-047). The refusal order (D-008: SS-089 to SS-091), the 4 MiB peer line (D-010: SS-109, DESIGN §14.1) and the deletion of covered `slot` entries from tier 0 (D-022: SS-108) need no DESIGN text.
     11. **Midnight takes roots, not events.** Puts, slot bindings, release anchors of `anchor_before_release` charters, the slot entries of `slot_anchor` and `RestoreDone` statements go to an append-only seat log on the board. Each Midnight checkpoint carries one Merkle root per seat over that log, and the new `RestoreDone` statements. An entry counts once a landed root covers it. Checkpoint signers refuse a root over a log with a second binding for one slot key or a second put of one digest. Authority: owner ruling 2026-11-14, "use the batched design you are insane to make that many commits to midnight save space, tokens, and transactions", with the standing rule of no per-event Midnight writes. The Veritee requirements: put rules SS-128 to SS-131, SS-137 and SS-138; anchors SS-070 to SS-073, SS-092, SS-119 and SS-139; `RestoreDone` SS-112, SS-117 and SS-120 to SS-122; the root chain SS-136; the batched bind SS-140 and SS-141 (O36). DESIGN §4.1, §7.4, §7.7, §7.13, §11.6, §14.3, O32. Claims C12, C16.
     12. **P2 seizure on ECDSA after a restart.** Without anchors the guardian slots `G_g` burn at a whole-committee restart, and their refill session needs the user online. A user who stays offline delays seizure until a refill runs. DESIGN §5.8.
   - Consequences:
     - Good: a whole-committee restart with tier 0 intact on `t` nodes keeps every key and every slot outside the burn sets. Pending requests outside the burn sets continue. A replacement VM reopens the sessions of its seat.
     - Good: no slot binds two tickets after a rollback of every disk. That holds outside the witness bound, because the burns rest on Midnight.
     - Bad: every whole-committee restart without anchors burns the unused ECDSA slots of every address, the guardian slots `G_g` included. Each ECDSA address and each P2 seizure path needs a refill session with every session party online. A recovery exit on an ECDSA chain also needs one (C15).
     - Bad: a release waits for one batched `release` round and two batched bind rounds (O36). Entry 38's "one peer round between the anchor and the release" no longer holds for TEE mode.
     - Bad: with `slot_anchor` or `anchor_before_release` a release also waits for the next checkpoint root, about one checkpoint interval plus Midnight finality. Midnight takes no transaction for it (§11.6).
     - Bad: a seat log entry is only as available as the board. A checkpoint root over a log that no reader can fetch in full makes `E` treat every slot of that seat as bound.
     - Neutral: the checkpoint shows the floor and the pending indices of each committee pool, by suite (§6.4 item 16). O35 narrows to the transport of the §3.6 session messages and the slot anchor of O32, because the enclave-side slot state already sits in sealed account pools under random ids.
     - Entries 38 and 50 stay as written.
     - The Sessions architecture names "new slots from the recovery group" in D-027 and "the recovery group reprovisions the unused ECDSA slots" in its proposal. Under (r3) that holds only with anchors on. D-027 and SS-128 to SS-131 put each entry in the seat log, as item 11 of this entry states.
   - Confirmation (each a planned check; none has run for this mapping):
     - outcome, model check: Sessions Quint items QI-01 (G2 with blank tier 0), QI-06, QI-13 and QI-19 (restart burns), QI-07 and QI-18 (restart marker), QI-17 (put records), QI-20 (losses counted while they last), (LOOP.md item 22). Targets SS-050 to SS-068, SS-102, SS-114, SS-123 to SS-133. Claims C12, C16.
     - outcome, model check: the item 26 DESIGN Quint model gains the reservation window at the vote and the restart burn on the committee pool, and checks that no later request binds an index at or below `h` that is not pending, that `E` never reshares an ECDSA slot that a covered seat log binds or that an unreadable log could bind, and that a batched bind with one refused slot releases nothing on that slot. Targets SS-050, SS-063, SS-064, SS-068. Claims C12, C16.
     - outcome, test: the cold start drill of O17. Claim C16.
     - outcome, measurement: the bind cost of O36.
   - Revisit when: item 29 renumbers the seat-log requirements of Sessions, O32 settles the slot anchor, O35 encrypts the slot session, O36 is measured, or the owner confirms or changes D-025 to D-031.

## Midnight writes per checkpoint

52. **The committee writes Midnight per checkpoint, epoch and boot, never per request.**
   - Context and problem: the owner's standing rule (2026-11-14) allows one Midnight transaction per checkpoint, epoch or batch, with one root or a few fixed-size fields, and keeps item data off-chain. The audit `midnight-writes-audit/veritee-linedealing.md` found five per-event sites in DESIGN. The committee submitted one `settle` per request (D2) and one relay per board-first call (D3). The checkpoint listed every pending slot index of every pool (D4) and every board-first `nf` not yet on Midnight (D5). Three sites had no stated place or count: actor pool keys (D9), the creator's `E_c` (D10) and one Key Registry record per node and epoch (D12). SCHEME allowed a host chain as the board (S1).
   - Drivers: C11, C12, C13, C16, O29; the owner's rule of no per-event Midnight writes; Sessions SS-005, SS-064, SS-068, SS-104 and D-034 (pending fields); Sessions Quint item QI-24.
   - Considered options:
     - D2: (a) keep one `settle` per request; (b) a `settle_root` per checkpoint only, so every next spend and every reissue waits up to 60 s plus `F_M`; (c) `settle_root` per checkpoint, with the VOID settlement carried in the reissue's `authorize` and checked by the contract in the clear; (d) as (c) with the carried settlement checked inside the proof, which needs a new committee key on Midnight's embedded curve and `q` signature checks in the circuit; (e) carried settlements for every outcome.
     - D4: (a) keep the pending list; (b) `pending_min` alone; (c) `pending_min`, `pending_root` and `pending_count`; (d) let the checkpoint signers check disjointness after a restart, off Midnight.
     - D3 and D5: (a) keep the relay and the checkpointed `nf` set; (b) one `bf_root` per checkpoint that is also the nullifier root of the batch.
     - D9: (a) one Midnight write per pool key; (b) one pool-key root per batch of `N_pk` keys, with membership proved in `authorize`.
     - D12: (a) `n` records per epoch; (b) one `EKS_e` record per epoch with `q` signatures.
   - Outcome:
     - D2 (c). The leaf is `(auth, outcome)`. `ic` commits to the intent, so `auth` and the outcome fix the successor, and the leaf needs no successor field that nodes could not check. FINAL and RELEASED count only by the root path. A carried FINAL could not be seen on Midnight, and after a whole-committee restart with a lost board tail the nodes could settle the same `auth` again with another outcome. A carried VOID is recorded on Midnight, so a replaying node refuses its request. (e) is rejected for that reason. (d) is rejected because it adds a key and circuit cost to hide a link that the same-block settlement already showed. The reissue link is a stated limit (§6.4 item 17). A request that a restart ends settles VOID only when its pinned input is unspent on the host chain, FINAL when the host shows its own transaction, and RELEASED otherwise.
     - D4 (c), the form of Sessions D-034. The contract rule after a restart is `cp2.h ≥ cp1.h + B` and `cp2.pending_min > cp1.h + B` for every pool. The restart burn is `[pending_min, h + B]`. The proof in DESIGN §7.13 shows that this burn holds every index of the list burn, that its extra indices can never bind, that the new rule implies the list rule, that an honest `cp2` passes it, and that a rollback of every disk changes neither, because both read only landed Midnight fields. `pending_root` lets seald check a pending index at `slot_bind` by a membership path, and seald refuses an index below `pending_min` from the checkpoint alone. (d) is rejected: it moves the restart rule off Midnight, the one place a rollback of every disk cannot reach.
     - D3 and D5 (b). The board refuses a second call on one `nf`, each node checks `nf` against the leaves of every landed `bf_root`, and the checkpoint signers refuse a `bf_root` that repeats an `nf`. The contract holds roots, not nullifiers, so it does not check duplicates. `FenrirAssets` takes no direct `authorize` for a board-first record. The root-age bound becomes the charter bound minus one checkpoint interval and `F_M`.
     - D9 (b), D10: `E_c` goes encrypted to the holder in the birth record. D12 (b): rotation opens every new epoch, so one record per epoch serves every node.
     - S1: SCHEME states that the board is not Midnight.
     - Authority: the owner's standing rule of 2026-11-14 on Midnight writes. The lead decides each option above under the owner's order to decide with reasons.
     - This entry replaces the checkpointed `nf` set of entry 50 item (5) and the pending list of entry 51 items 4 and 5.
   - Consequences:
     - Writes before and after, at `n = 9` and `n = 17`, at 160 to 400 requests per second:

       | Write | Before | After |
       |---|---|---|
       | Committee `settle` | 1 per request: 160 to 400 per second, 9,600 to 24,000 per 60 s | 0; one 32-byte `settle_root` per checkpoint |
       | Committee board-first relay | 1 per board-first request, up to 160 to 400 per second | 0; one 32-byte `bf_root` per checkpoint |
       | Reissue | 2 `authorize` and 2 `settle` | 2 `authorize`, the second carries the VOID settlement (about 420 B at `n = 9`, 800 B at `n = 17`) |
       | Checkpoint | 1 per 60 s, with 4 B per pending index: about 1.5 to 3.8 MB at 600 s request life, 9 to 23 MB at 3,600 s; plus 32 B per board-first `nf` in flight | 1 per 60 s, fixed: 1,008 B at `n = 9`, 1,712 B at `n = 17` |
       | Key Registry | 9 or 17 records per epoch | 1 record per epoch: 1,621 B or 3,069 B |
       | Actor pool keys | not stated; up to one write per pool, about 0.47 per request per named actor | one root per `N_pk = 1,024` pools, about one per 2,000 requests per named actor |
       | Committee transactions per second | 160 to 800 | 1/60 |

     - Good: committee writes no longer grow with the request rate. Only the user's `authorize`, birth, refill and pool-key root writes do.
     - Good: the restart rule stays a contract rule, so C16 holds after a rollback of every disk as before.
     - Bad: the next spend after FINAL waits up to one checkpoint interval plus `F_M`.
     - Bad: `authorize` gains a settle-root path and a pool-key membership path (O37). A reissue shows its link to the stalled request (§6.4 item 17).
     - Bad: board-first calls ordered after the latest landed checkpoint exist only on the board. A whole-committee restart that loses the board tail forgets them, so a second call on one `nf` can come into force. The pinned host input still bounds the host chain to one spend (COUNTEREXAMPLES B1, OPEN DESIGN, O29).
     - Neutral: the Veritee committee-signing items V1, V2 and V6 of the audit belong to the Veritee lane.
   - Confirmation:
     - outcome, model check: `design/enhancement/quint/batched_checkpoint.qnt`, invariants `C12_C16_oneTicketPerSlot`, `C16_burnCoversList`, `C16_pendingMinRuleImpliesListRule`, `C13_honestCheckpointLands`, `C11_oneOutcomePerAuth`, `C11_oneAuthorizePerState`, `C11_noLostSuccessor`, `C11_settledByCheckpoint`, `C11_bfNoDupInForce`, `C11_bfLandedDisjoint`, `C11_bfOneHostSpend`. Result (`run-batched.sh` under `heavy-run`): typecheck passes, four `run` tests pass, the design run of 20,000 traces of 40 steps shows no violation, five reachability witnesses are reached, and each of eleven mutants breaks its named invariant. With the board tail lost, `C11_bfNoDupInForce` fails and `C11_bfOneHostSpend` holds (COUNTEREXAMPLES B1). Targets: Sessions QI-24, SS-064, SS-068, SS-104.
     - outcome, test: Sessions prototype `proto/sessions-sim` tests `pending_min_restart_jump_refused_and_accepted` and `sequential_pending_membership_requires_matching_root` (D-034). Targets SS-064, SS-104.
     - outcome, measurement: O37.
   - Revisit when: O29 or O37 closes, Midnight publishes a finality time or a transaction size, or the owner changes the write rule.

53. **A request that a whole-committee restart ends settles FINAL or RELEASED, never VOID.**
   - Context and problem: §5.6 settled a request that ended after the latest landed checkpoint and before a whole-committee restart as VOID when its pinned input was unspent. The release evidence of that request (RELEASE votes on the board, witnessed `release` entries) can lie in the lost board tail and in rolled-back witness logs. A partial may have left, and the transaction it completes can confirm after the settlement. A VOID settlement returns the record to unspent with a fresh nullifier, so a later authorization can spend the record state again: on an account chain with a new nonce, so two transactions confirm; in P2 around a hold placed on the unspent record.
   - Decision: a node settles every request that a whole-committee restart ends as FINAL when the host chain shows one of its variant transactions at confirmation depth, and as RELEASED otherwise. The record stays locked to the pinned input or nonce, and the owner's re-post spends it. §5.6, §7.11 items 1 and 2 and the non-TEE paragraph state the rule.
   - Rationale: no node can show after the restart that no partial left. RELEASED keeps C11 at one spend per record state. The re-post already spends the pinned input, so the lock costs nothing.
   - Consequences:
     - Good: C11 and the P2 hold hold across a whole-committee restart that loses the board tail.
     - Bad: a request that never released a partial also settles RELEASED after such a restart. Its owner re-posts with the same pinned input or nonce.
   - Confirmation:
     - outcome, model check: `formal/quint/splitline.qnt`, invariant `C11_ReleasedNeverUnspent`, mutant `m_cold_void` (the old rule) violates it, design instances hold. Finding S4 in `tests/quint-regressions/splitline/COUNTEREXAMPLES.md`.
     - outcome, test: `design/enhancement/vectors/quint_counterexamples.py` case S4: under the old rule a released ECDSA partial completes a transaction with nonce `n` after the VOID settlement, and a new authorization with nonce `n + 1` confirms as well; under the new rule the second authorization must use nonce `n` and one transaction confirms.
   - Revisit when: seald's `anchor_before_release` is on for every charter, so release entries are covered by a checkpoint root before a partial leaves.

54. **ECDSA precedence starts at the authorization, and the slot rules of §4.1, §4.5, §4.6 and §5.11 agree.**
   - Context and problem: the review of the split-line paper found four places where DESIGN disagrees with itself or with its own attack model (paper-split/review/TRIAGE.md, review findings G5 and G13 and the list "Findings for the design specification").
     1. §4.1 burns every named slot when the request with precedence ends or lapses. §4.5 item 4 burns only reserved slots.
     2. §4.6 gives a contribution frame `auth_ref` zero. The same section gives every envelope without an authorization 32 random bytes, so that the field does not show the request type.
     3. The §5.11 leaf-set row says that two leaf sets leak "the committee's halves x". Two evaluations of one group's half line give the group's half line only. Recovering `x` also needs the halves of every other actor on the slot (§3.6).
     4. Review finding G5. §4.1 gives precedence by board order before the authorization is in force, and a lapse or an end burns the named slots. ECDSA slot ids belong to one address and the committee knows them. Anyone can name them in envelopes that need no authorization, void the requests that use them with SLOT_TAKEN, and burn them. A P2 user can burn the guardian slots `G_g` and stay offline. The refill needs every session party online, the user included, so the seizure waits (§5.8).
   - Drivers: C12, C13, C21 (frame shape), the P2 seizure path of §5.8, O34.
   - Considered options for item 4:
     - (a) Keep board-order precedence for ECDSA slots and rely on the refill. Rejected: the refill needs the attacker, a P2 user, online.
     - (b) An ECDSA slot takes precedence only from a request whose authorization is in force and whose source opens the slot's root (§5.3 item 4). Earlier namers without one take nothing.
     - (c) Keep precedence before the authorization and burn nothing on a lapse. Rejected: the unauthorized namer still voids the authorized request with SLOT_TAKEN while it is live, and can post again.
   - Decision:
     1. §4.1 is the rule for committee slots: the request with precedence burns every named committee slot when it ends or lapses. §4.5 item 4 now says so, and adds the ECDSA rule of item 4.
     2. A contribution frame carries 32 random bytes in `auth_ref`, as every envelope without an authorization. The definition `pub*` with `auth_ref` set to zero inside `hd` stays.
     3. The §5.11 row states the leak of §3.6: the group's shard, and `x` only with the halves of every other actor on the slot.
     4. Option (b). An ECDSA slot is burned when a request that reserved it ends. §4.1, §4.5 item 4, §5.8, C13 and the §9.3 row "C6, C13" carry it. New open item O38.
   - Rationale: committee slot ids carry no account and are dealt to anyone, so the pool cost of spam is the bound that O34 sizes. An ECDSA slot belongs to one address and is refilled only with every session party online, so a burn by an outsider is a denial of service on that address. Only the record's own sources can have an authorization in force that opens its slot root, and Midnight accepts one `authorize` per `nf`. A copy of a header therefore takes no ECDSA slot under (b). A slot that no request reserved holds no partial, because no node releases before the authorization is in force (C6). It needs no burn.
   - Consequences:
     - Good: an envelope without an authorization in force voids no ECDSA request and burns no ECDSA slot. A P2 user cannot delay a seizure by naming the guardian slots.
     - Good: CONTRIB frames have the public shape of every other frame.
     - Bad: an authorized ECDSA request can take a slot from an earlier unauthorized namer. That namer ends VOID with SLOT_TAKEN when its own authorization comes into force later. Only the record's own sources can be in that position.
     - Neutral: committee slot spam is unchanged and stays in O34.
   - Confirmation:
     - outcome, model check: `formal/quint/splitline.qnt`, rule `ecdsaPrecInForce`, invariants `C13_EcdsaPrecOnlyInForce`, `C13_EcdsaNoBurnByUnauthorized`, `C13_EcdsaSlotTakenOnlyByInForce`, `C13_EcdsaBurnOnlyIfReserved` and `C20_NoLaterTakesEarlierSlot` (restated for ECDSA); mutant `m_g5` (the old rule) violates them; `C13_EcdsaNamedOnlyWhileInForce` states that precedence ends with the authorization; scripted runs `g5VoidBroken` and `g5BurnBroken` (pass on `gt_m_g5`) and `g5VoidHolds`, `g5VoidRefusedHolds` and `g5BurnHolds` (pass on `gt_design`) in `formal/quint/splitline_test.qnt`; on the account pool of `formal/quint/splitline_pools.qnt`, rule `acctPrec` and invariant `C13_AcctEarliestHolds`, killed by `acctEarliestBroken` on `pt_acct_race`. Finding G5 in `tests/quint-regressions/splitline/COUNTEREXAMPLES.md`. Targets C12, C13.
     - outcome, model check: `formal/quint/splitline_pools.qnt` burns a committee slot at the end of the request with precedence and an account-pool slot at the end of the request that reserved it.
     - outcome, proof: O38.
     - Items 2 and 3 change text with no protocol state, so no model check applies.
   - Revisit when: O38 closes, a charter source can open another record's slot root, or ECDSA slots move into a committee pool.

## Base-board rules from the conformance replay of impl/ (item 6 gaps G1, G2)

Entries 55 and 56 close the two OPEN DESIGN verdicts of `tests/quint-regressions/COUNTEREXAMPLES.md`. Both apply to the line-dealing board of SCHEME §3.10 and §5 and to the split-line request state machine of §5.1 and §5.6.

55. **A FINAL or VOID post counts at its board position; the poster validates its evidence.**
   - Context and problem: SCHEME §3.10 says that `f + 1` FINAL or VOID posts set the tombstone, and does not say who validates a post or when. `impl/` validated each post against the evaluating node's own chain view when the post arrived, and dropped a post that the view did not back yet. The Quint model counts every FINAL or VOID post of a committee member at its board position. The two rules differ when a post arrives before the evaluator's chain shows the transaction at depth: a premature Byzantine FINAL plus one honest FINAL is FINAL in the model and not in `impl/` (counterexample G1, n = 4, f = 1). The arrival rule also makes the tombstone depend on each node's chain lag, so two honest nodes can disagree on the status of one request at one board position.
   - Drivers: SCHEME §3.10, claim 7 (liveness), DESIGN §5.1 (FINAL and VOID are vote counts on the board), C13; DECISIONS 50(6) (STALLED is a board predicate).
   - Considered options: (a) validate at arrival and drop for good (the old `impl/` rule); (b) keep the post and count it once the evaluator's chain backs it, which needs a re-evaluation on every chain step and still depends on the evaluator's lag; (c) the poster validates its own evidence before it posts, and the board counts authenticated posts of members at their board positions.
   - Outcome: (c). An honest node posts FINAL(txid) only when its own chain view shows `txid` at the confirmation depth, and VOID only when it sees a foreign spend of the pin. The board records every authenticated FINAL or VOID post of a committee member at its position, and the tombstone forms at the first position where `f + 1` distinct members of one epoch have posted FINAL with one `txid` (SCHEME) or `q` FINAL votes with one `Enc_{k_fin}(txid)` (DESIGN §5.6), or `f + 1` VOID posts. FINAL before VOID is decided by board position. Authority: lead decision under owner delegation, 2026-11-14.
   - Consequences: the tombstone is a function of the board alone, so every honest node computes the same status at the same position. Every counting set holds one honest poster, so the adversary cannot finalize or void alone. A Byzantine post can make an early honest post sufficient one post sooner. That is safe, because the honest post carries the evidence. The `valid` flag of `Event::Final` and `Event::ForeignSpend` in `impl/` gates the honest poster, not the board count.
   - Confirmation: conformance, `impl/tests/quint_conformance.rs` replays the model traces with no G1 tolerance; unit test `g1_final_counted_without_evaluator_chain_view` in `impl/src/board.rs` (the former counterexample, now a regression test); split-line state machine test of the same rule.
   - Revisit when: a host chain without deterministic finality at a fixed depth is added, or a post carries its evidence in a form the board can check (an SPV proof).

56. **After HANDOVER each committee that served a request counts its own FINAL and VOID posts.**
   - Context and problem: SCHEME §5 says that the old committee finishes the in-flight generations and the new committee resumes the others. It does not say whose FINAL or VOID posts count after HANDOVER. `impl/` counted an old-committee post only while the old committee still had a generation in flight, so an old node that saw the transaction confirm after HANDOVER could not help end the request. The model counts honest old-committee posts at any time (counterexample G2).
   - Drivers: SCHEME §5 and §3.10, DESIGN §8.1 step 7 (old nodes keep their keys until the grace period ends), claim 7, C13.
   - Considered options: (a) count old-committee posts only while it has a generation in flight (the old `impl/` rule); (b) count every post of any epoch in one set; (c) count each epoch that served the request against its own threshold, at any time, never adding posts across epochs.
   - Outcome: (c). A FINAL or VOID post counts when its author is a member of an epoch that serves the request: the binding epoch, or a successor epoch from the board position of the ROTATE that registers it, before or after HANDOVER, until that epoch's post keys expire with the grace period. A post under an epoch that is not registered at its position cannot be authenticated and is refused. VOID counts distinct members whatever foreign txid each reports, because the pin is spent once. Each epoch's posts are compared with that epoch's own `f + 1` (or `q`). Posts of two epochs are never added together, because `f` Byzantine nodes of one epoch and `f'` of the next could otherwise reach a threshold with no honest post. Authority: lead decision under owner delegation, 2026-11-14.
   - Consequences: a request whose transaction confirms during a rotation ends as soon as either committee has its threshold. The old committee needs no in-flight generation to observe a confirmation. Nothing changes for key material: FINAL and VOID use post keys only.
   - Confirmation: conformance, the replay with no G2 tolerance; unit test `g2_old_committee_final_counts_after_handover` in `impl/src/board.rs`, with negative cases for `f` posts and for posts mixed across epochs. The replay classifies one model trace as artifact M2 (a post by an epoch before its ROTATE), verdict GUARD HOLDS in `tests/quint-regressions/COUNTEREXAMPLES.md`.
   - Revisit when: the grace period of §2.3 changes, or rotation keeps old post keys past HANDOVER for another purpose.

## Envelope framing from the prototype (item 11)

57. **The frame carries a fixed authenticated layout block, and every actor capsule has one size.**
   - Context and problem: §4.6 hides the lengths of `body_0`, the variant bodies and the capsules, so the frame did not say where an encrypted region ends. The prototype found the end of `body_0` by trial AEAD over every candidate length. That work grows with the square of the frame size: 7.4 ms per header open at `n = 9`, against 0.45 ms for the rest of the step. A combiner and a contribution frame paid the same scan. An actor did not know `K`, so it tried an HPKE open for each of the eight capsule sizes at each position.
   - Drivers: C8 (sealed until order), §4.6 (the public part names no chain, suite or variant count), §11.3 node CPU, §5.10 rules 7 and 8 (no full work on the optimistic path; work for the selected body only).
   - Considered options:
     - (a) Keep the trial scan.
     - (b) Put the region lengths in the public part. This shows `K`, `L` and `G` before the QC and breaks the blind ordering of §4.6.
     - (c) Put the lengths at the start of the header plaintext. The node must still find the end of the header ciphertext, so the scan stays.
     - (d) A fixed-size block `lay = AEAD(k_lay, layout)` after the outer dealing, with `k_lay = KDF(Z_hdr ‖ "layout")`, and actor capsules padded to `K_max = 8` capsule keys.
   - Outcome: (d). The layout holds 24 big-endian 2-byte lengths: `body_0`, 15 body regions and 8 capsule regions, with zero for each unused entry. `lay` is 64 bytes in every frame. `k_lay` is a separate HKDF purpose of the combined `Z_hdr`, so each key still encrypts one message under the zero nonce, and the node needs no extra partial. `lay` is inside `hd` and outside `dd`. A contribution frame carries a layout of the same size with zero body and capsule lengths. The actor capsule holds `k_hdr`, `k_lay`, the position, `τ_a` and eight capsule keys, unused ones zero: 385 bytes. Authority: lead decision under owner delegation, 2026-11-14.
   - Consequences:
     - Good: the header open is one layout AEAD and one header AEAD. An actor runs one HPKE open per position. Measured header open: §11.3.
     - Good: the public part, `lay` and the actor capsules have one size for every request, so ordering stays blind to `K`, `L` and `G`.
     - Bad: each request grows by 64 bytes. Each other actor grows by 32 bytes for `k_lay`, and by `32·(8 − K)` bytes for the padding. The signing sets per frame of §11.1 shrink most at small `K`: at `K = L = 1` the frame holds 29 to 33 signers, where it held 59 to 75.
     - Neutral: an actor that holds `k_lay` learns the region lengths. It already reads the header and every capsule with `k_hdr` and the capsule keys.
   - Confirmation:
     - conformance, test: `impl/tests/split_envelope.rs` checks layout authentication, canonical lengths, separate HKDF purposes, the fixed actor capsule width, padding and the frame capacity per grid; `impl/tests/split_e2e.rs` runs every suite end to end through the layout.
     - outcome, measurement: `impl/benches/split.rs` rows `header_combine_open` and `contrib_frame_open` (§11.3, §11.5).
     - The change has no protocol state: the layout is framing inside one envelope. Unit tests cover it in place of a Quint check.
   - Revisit when: a second size class is added, `K_max` or `G_max` changes, or a notification channel gives each actor its capsule size.

## Restart settlement leaves (item 12, Q-008)

58. **A restart leaf supersedes a settlement leaf that Midnight does not hold; a leaf that Midnight holds is never replaced.**
   - Context and problem: RQ-068 ends again a request that ended after the latest landed checkpoint when a whole-committee restart burns one of its slots, and settles it FINAL or RELEASED by the rule of entry 53. The nodes may already have signed a settlement leaf `(auth, outcome)` for that request on the board, for example `(auth, VOID)` after a STALL. §5.6 says that honest nodes sign one outcome per `auth` (RQ-054), so RQ-068 and RQ-054 contradict each other for such a request.
   - Drivers: C11 (one spend per record state), §5.6 (one outcome per `auth` under every landed root), entry 53 (restart ends settle FINAL or RELEASED).
   - Considered options:
     - (a) The restart leaf of RQ-068 supersedes every leaf of the same `auth` that Midnight does not hold. A leaf that Midnight holds is never replaced.
     - (b) Keep the first leaf, and RQ-068 does not fire when a leaf exists. Rejected: a request whose variant confirms after the restart keeps a VOID or RELEASED leaf, so a confirmed spend is settled RELEASED or the record returns to unspent, and C11 breaks.
     - (c) Allow two leaves per `auth`. Rejected: it breaks the one-outcome-per-`auth` rule of §5.6.
   - Decision: (a). Midnight holds a leaf when a landed `settle_root` covers it or when a reissue's `authorize` carried it as a VOID settlement (§5.9). A request that ended after the latest landed checkpoint has no leaf under a landed `settle_root`. A carried VOID leaf belongs to a STALLED request, which released nothing (RQ-057), and a node that replays it refuses the request as settled (RQ-061), so the restart gives it no second outcome. Authority: lead decision under owner delegation, 2026-11-15.
   - Rationale: an uncovered leaf has reached no on-chain verifier, so replacing it changes no state that Midnight or a wallet proof has accepted. The variant of a request that ended VOID can still confirm after the restart, and then only FINAL is true. The one-outcome-per-`auth` rule of §5.6 holds for every landed root.
   - Consequences:
     - Good: RQ-054 and RQ-068 agree, and C11 holds across a whole-committee restart.
     - Bad: a wallet that kept the path of an uncovered leaf must drop it after a restart and wait for the restart leaf under the next landed `settle_root`.
   - Confirmation:
     - conformance, Lean oracle (LOOP item 13): RQ-054 and RQ-068 as transitions; a covered leaf never changes, an uncovered leaf of a re-ended request takes the restart outcome. Planned.
     - outcome, Quint model (LOOP item 14): the C11 invariant across a whole-committee restart; option (b) as a mutant violates it. Planned.
   - Revisit when: seald's `anchor_before_release` is on for every charter, or the settlement leaf moves to Midnight per request.

## Fixes for the spec-only Quint findings (item 14, F1 to F6)

Entries 59 to 63 close the five findings of `formal/quint-spec/FINDINGS.md`. The Quint model of item 14 was written from the specs only. Each entry names the spec sentences it changes. The model checks each fix as an invariant of its gate, with the finding schedule as a regression test and the old rule as a mutant. Entry 64 closes F6, which the revision 3 run found. Entries 53 and 54 live on branch quint-split and keep their numbers.

59. **A non-TEE node sends no release partial before its RELEASE is on the board; a request with a recorded send settles RELEASED.**
   - Context and problem: in NON_TEE mode RQ-030 let a node send its PRF and signature partials before its RELEASE vote committed (RQ-037). Finding F1 (schedule `f1NonTeeExpiryDoubleSpendTest`): the partials of request 1 leave the nodes, no RELEASE commits, the request expires and settles VOID by RQ-050, AU-023 returns the record to UNSPENT with a fresh nullifier, the re-post takes a new pin, and the host chain confirms both transactions. AU-024 breaks. TEE mode records the release at `w` peer acks before the send (RQ-035), so F1 occurs only in NON_TEE mode.
   - Drivers: C11 (one spend per record state), AU-024, entry 47 (a request with a release never settles to unspent), §5.6 step 4 (a non-TEE node records RELEASE in its vote), entry 52 (no committee Midnight write per request).
   - Considered options:
     - (a) A non-TEE node posts RELEASE for `(g, j)` in its board vote and sends no partial of generation `g` until that RELEASE has committed for the ADMITTED request. The committed RELEASE sets `any_release` (RQ-037), so the request settles RELEASED and the record stays LOCKED to its pin.
     - (b) Settle the request VOID and rely on the host chain to refuse a second spend. Rejected: VOID returns the record to UNSPENT with a fresh nullifier, the next authorization takes another pin, and the F1 schedule confirms two spends of one record state, against AU-024.
     - (c) Combiners report each combined signature on the board. Rejected: a partial that left a node can combine off the board at a corrupt combiner, which reports nothing.
   - Decision: (a). RQ-030 lists the new RQ-069 among the release checks, and RQ-069 states the order: RELEASE committed, then send. RQ-050 and RQ-051 keep their statements; their notes record that `any_release` now covers every honest send. RQ-005 refuses a RELEASE that reaches the board after the request ended, and the node then sends nothing. Authority: lead decision under owner delegation, 2026-11-15 (item 14 findings).
   - Rationale: a combined signature needs `t = n − f > f` partials, so at least one honest partial. An honest partial leaves only after its RELEASE committed, so every signature that can confirm belongs to a request with `any_release = true`, which RQ-051 settles RELEASED.
   - Consequences:
     - Good: C11 holds in NON_TEE mode without help from the host chain.
     - Bad: a non-TEE release waits for one board commit after the RELEASE post, one board block per generation.
     - Bad: a node that recorded RELEASE and then sees a revocation sends nothing, but the request still settles RELEASED and the record stays locked to the pin.
     - Neutral: the record is one entry in the node's existing board vote. The committee writes nothing more to Midnight.
   - Confirmation:
     - outcome, Quint model `formal/quint-spec`: `f1NonTeeExpiryDoubleSpendBlocked1Test` (a send before the committed RELEASE fails) and `f1NonTeeExpiryDoubleSpendTest` (with the record the request settles RELEASED and the second confirmation fails); mutant `send_before_record` restores the old order and breaks `inv_AU024_C11_oneSpendPerRecordState`; `inv_RQ069_C11_sentNeverVoid` and `inv_AU024_C11_oneSpendPerRecordState` are in the gate.
     - conformance, Lean oracle (LOOP item 13): RQ-069 as a refusal of a send without a committed RELEASE. Planned.
   - Revisit when: non-TEE mode gains a peer witness like RQ-035, or the board can carry a release proof that a combiner cannot withhold.

60. **A VOID settlement on a LOCKED record keeps the record LOCKED to the same pin.**
   - Context and problem: AU-023 made every VOID successor UNSPENT. Finding F5 (schedule `f5LockedVoidUnlocksTest`): request 1 releases, expires and settles RELEASED, so the record is LOCKED to pin 1. Its re-post authorizes on pin 1 (AU-005 item 1), expires with no release and settles VOID. AU-023 returns the record to UNSPENT with a fresh nullifier, the lock is gone, the next authorization takes pin 2, and both the RELEASED transaction of request 1 and the spend of pin 2 confirm. AU-025 did not forbid this, because the record that returned to UNSPENT was the re-post's successor. The Lean oracle of item 13, written apart from this model, reached the same state and recorded that it contradicts entry 47.
   - Drivers: entry 47 (D-047: settle a released request as RELEASED, locked to its pinned input, and let a later authorization spend only that input), C11, AU-024, AU-025.
   - Considered options:
     - (a) When an authorization accepted on a LOCKED record settles VOID, its successor stays LOCKED to the same pin under the VOID nullifier (new AU-029). AU-025 covers every later successor up to the change record of a FINAL settlement.
     - (b) Refuse every authorization on a LOCKED record until the pin is spent. Rejected: a P2 hold or seizure must spend the same input (entry 47), and a fee bump on the pin is a new request.
     - (c) Keep AU-023 and make the wallet reuse the pin. Rejected: C11 must hold in the contract, and a wallet can choose another pin.
   - Decision: (a). It restores entry 47. The rule applies to a root settlement (AU-020) and to the carried VOID of AU-021. Authority: lead decision under owner delegation, 2026-11-15 (item 14 findings).
   - Consequences:
     - Good: a released transaction can still confirm, and no other spend of the record can, whatever later requests do.
     - Bad: a record whose released transaction never confirms stays locked to that pin until a request spends the pin and settles FINAL. The owner cannot move the coin by another input.
     - Neutral: the contract reads the record state at acceptance, where AU-005 item 1 binds `pin`. No new field.
   - Confirmation:
     - outcome, Quint model `formal/quint-spec`: `f5LockedVoidUnlocksTest` is a regression test (after the VOID settlement the record stays LOCKED to pin 1, the next authorization takes pin 1, and the second confirmation fails); mutant `locked_void_unlocks` restores the old AU-023 and breaks `inv_AU025_C11_releasedNeverUnspent`; `inv_AU025_C11_releasedNeverUnspent` is in the gate.
     - conformance, Lean oracle (LOOP item 13): AU-029 as a transition. Planned.
   - Revisit when: a host chain without a pinned input or nonce is added (as for entry 47).

61. **The reason of a VOID tombstone is the reason that `f + 1` posts carry, otherwise MIXED.**
   - Context and problem: RQ-045 took the reason of the post that completes the `f + 1` count (Q-002, provisional). Finding F2: a corrupt member that completes the count chooses the reason. The schedule `f2CorruptReasonTest` gives REVOKED in a P1 charter, where AU-019 rules out revocation, and random runs give STALLED on a request that released (seeds 0x4887c5 on `tee_p1`, 0x476170 on `nontee_p2`), against C20. Three rules read the reason: the SLOT_TAKEN half of RQ-063 (C13), the stalled gate of AU-021 (C20) and the revocation cause of AU-019 and RQ-034.
   - Drivers: C13, C20, Q-002, RQ-042 (every counting set holds an honest post), entry 55 (a post counts at its board position).
   - Considered options:
     - (a) The tombstone reason is the reason that at least `f + 1` of the counted posts carry. If none reaches `f + 1`, the reason is MIXED, and no rule reads MIXED as STALLED, SLOT_TAKEN or REVOKED (new RQ-071 and RQ-072).
     - (b) The reason of the first post. Rejected: a corrupt member posts first as easily as last.
     - (c) A fixed priority order of reasons. Rejected: a corrupt post of the top reason always wins.
     - (d) Count only honest reasons. Rejected: the board cannot tell an honest post from a corrupt one.
   - Decision: (a). Q-002 is resolved. RQ-065 adds MIXED to the reason domain. The SLOT_TAKEN half of RQ-063 now reads an honest SLOT_TAKEN post, so a MIXED tombstone of a valid request still meets C13. Authority: lead decision under owner delegation, 2026-11-15 (item 14 findings).
   - Consequences:
     - Good: every named reason has an honest post, so a corrupt member cannot name it alone. REVOKED needs a revocation, and STALLED needs an honest node that saw `exp_c` pass with no `q` ADMIT votes.
     - Bad: a request whose honest posts name two causes ends MIXED and cannot use the carried VOID reissue. Its VOID leaf settles by root, one checkpoint interval later.
     - Neutral: the outcome rules (RQ-049 to RQ-052) do not read the reason.
   - Confirmation:
     - outcome, Quint model `formal/quint-spec`: `f2CorruptReasonTest` is a regression test (an honest MALFORMED post and a corrupt REVOKED post give MIXED); mutant `completing_reason` restores the old RQ-045 and breaks `inv_RQ045_RQ072_C13_C20_reasonHasHonestPost`; `inv_C20_stalledReleasedNothing` is in the gate.
     - conformance, Lean oracle (LOOP item 13): RQ-045 and RQ-072 as transitions. Planned.
   - Revisit when: a VOID post carries evidence that the board can check.

62. **Nodes refuse an envelope whose collection window reaches its expiry.**
   - Context and problem: EN-021 makes `exp_c < exp` a duty of the initiator wallet, and no public check of EN-004 to EN-008 enforces it. Finding F3: with `exp_c ≥ exp`, RQ-046 expires the request first, STALLED (RQ-047) never fires and the reissue of AU-021 is not available. The witness `w_exp_c_not_below_exp` was reached in 49% to 57% of the traces of the 16 design runs.
   - Drivers: C20 (reissue after STALLED), C13, RQ-047, §5.9 step 1 (the initiator keeps `exp_c < exp`).
   - Considered options:
     - (a) A public check EN-023: a node refuses to accept an envelope when the board height `b` that would order it gives `b + Δ_c ≥ exp`, code `exp_c_not_below_exp`. The node runs it at acceptance and again for the ordering block. EN-021 stays the wallet's duty.
     - (b) Clamp `exp_c` to `exp − 1` at ordering. Rejected: it moves the deadline that actors read for their contributions (§3.10).
     - (c) Keep the wallet duty only. Rejected: a faulty wallet then loses the reissue path, and the nodes cannot tell.
   - Decision: (a). RQ-003 names EN-023 among the public checks. `Δ_c` is a committee parameter (RQ-001), so every node can run the check before order. Authority: lead decision under owner delegation, 2026-11-15 (item 14 findings).
   - Consequences:
     - Good: every ordered request has `exp_c < exp`, so the STALLED path is always open before the expiry.
     - Bad: an envelope posted close to its `exp` is refused, and the wallet posts it again with a later `exp`.
     - Neutral: one comparison per envelope.
   - Confirmation:
     - outcome, Quint model `formal/quint-spec`: `inv_EN023_expCBelowExp` in the gate replaces the witness; `en023ExpCRefusedTest` shows the refusal; mutant `exp_c_unchecked` orders without the check and breaks the invariant.
     - conformance, Lean oracle (LOOP item 13): EN-023 as a refusal. Planned.
   - Revisit when: `Δ_c` becomes a field of the sealed header, so that no node knows it before order.

63. **A precedence lapse is a state of the request, not an event at `b + Δ_c`.**
   - Context and problem: SL-005 fired once, at board height `b + Δ_c`. Under the wait of Q-003 a header opens only after every earlier-ordered live envelope opened or ended. Finding F4: a header that opens after `b + Δ_c` takes precedence after the lapse event, nothing marks it lapsed, and its committee slots wait until `exp`. The witness `w_open_after_lapse` was reached in 10.6% to 17.1% of the traces.
   - Drivers: C13 (slots of a request that cannot come into force must not block others), §4.1 (precedence lapses when the authorization is not in force by the ordering height plus `Δ_c`), SL-010 (a lapse burns the slot), Q-003.
   - Considered options:
     - (a) State-driven SL-005: while the board height is at least `b + Δ_c` and the authorization was not in force at `b + Δ_c`, the precedence of the request is lapsed on every slot where it holds `prec`, also on a slot that it takes later. SL-010 burns such a slot at once.
     - (b) Run the lapse event again when a header opens. Rejected: the same effect with a second trigger that every new event that sets `prec` must repeat.
     - (c) Refuse to open a header after its lapse height. Rejected: a header that never opens holds back every later header under Q-003 until it ends at `exp`.
   - Decision: (a). The lead's rule reads "while the authorization is not in force at any board height at or above `b + Δ_c`". An authorization in force stays in force (AU-010), so that condition is the one at `b + Δ_c`, and SL-005 states it that way to match §4.1. Authority: lead decision under owner delegation, 2026-11-15 (item 14 findings).
   - Consequences:
     - Good: a request that is not in force by `b + Δ_c` holds no live precedence after that height, whenever its header opens.
     - Bad: a request whose authorization finalizes after `b + Δ_c` loses its slots even if its header opens later; the wallet posts it again.
     - Neutral: no new field; the lapse reads `order_pos` and the in-force height.
   - Confirmation:
     - outcome, Quint model `formal/quint-spec`: `inv_SL005_SL010_lapsedPrecBurned` in the gate replaces the witness; `sl005LateOpenLapsedTest` opens a header after its lapse height; mutant `lapse_once` restores the event rule and breaks the invariant.
     - conformance, Lean oracle (LOOP item 13): SL-005 as a state predicate. Planned.
   - Revisit when: Q-003 is resolved another way, or `Δ_c` becomes a per-request value.

64. **A request with a committed RELEASE never takes reason STALLED; late admission stays allowed.**
   - Context and problem: RQ-047 makes every honest node post STALLED when the board reaches `exp_c` with no `q` ADMIT votes committed. No rule refuses an ADMIT vote after `exp_c`. Finding F6: an honest STALLED post at `exp_c`, then the `q` ADMIT votes, a RELEASE and a corrupt STALLED post give `f + 1` STALLED posts with one honest, so entry 61 names STALLED on a request that released. The outcome stays RELEASED (RQ-051) and C11 holds, but the stalled gate of AU-021 reads STALLED on a request that released, against C20. The scripted schedule is `f6StalledAfterAdmitTest`; random runs reached it on `nontee_p1` (seeds 0x14 and 0x2a3, one schedule).
   - Drivers: C20 (a stalled request releases nothing), AU-021 (the stalled gate reads the tombstone reason), RQ-037 (`any_release` marks a committed RELEASE), entry 61 (the reason needs `f + 1` posts).
   - Considered options:
     - (a) Keep late admission. Once `any_release = true`, a STALLED post of the request counts toward the `f + 1` posts that form the VOID tombstone but not toward its reason. The reason is the reason that `f + 1` of the remaining posts carry, otherwise MIXED. A request with `any_release = true` never has reason STALLED (new RQ-073 and RQ-074; RQ-045 and RQ-072 count reason posts).
     - (b) Close admission at `exp_c`: no ADMIT vote at or after `exp_c`, none after the node's own VOID post. Rejected by the owner: a request whose last contribution arrives late but is admitted and released is a normal run, not a stall.
     - (c) Stop counting STALLED posts toward the tombstone after a RELEASE. Rejected: the tombstone then waits for other posts, and RQ-042 and RQ-045 change for one reason only.
   - Decision: (a). With a STALLED post among the `f + 1` posts of the tombstone, the remaining posts are at most `f`, so the reason is MIXED; a tombstone of `f + 1` posts without a STALLED post keeps the reason of entry 61. Authority: owner ruling, 2026-11-15 (item 14 finding F6). It replaces the lead's first rule (option (b)), which was not committed.
   - Consequences:
     - Good: AU-021 reads STALLED only on a request that released nothing, so the carried VOID settlement of a reissue never covers a released request. Admission keeps its whole window up to `exp`.
     - Bad: a released request whose tombstone holds a STALLED post ends MIXED and its leaf settles by root, one checkpoint interval later.
     - Neutral: the outcome rules (RQ-049 to RQ-052) do not read the reason; the tombstone forms as before.
   - Confirmation:
     - outcome, Quint model `formal/quint-spec`: `f6StalledAfterAdmitTest` is a regression test that ends with reason MIXED and outcome RELEASED; `inv_RQ073_C20_noStalledAfterRelease` and `inv_C20_stalledReleasedNothing` are in the gate; mutant `stalled_after_release` counts STALLED posts after a RELEASE again and breaks both on the F6 schedule.
     - conformance, Lean oracle (LOOP item 13): RQ-045, RQ-072 and RQ-074 as the tombstone transition. Planned.
   - Revisit when: a STALLED post carries evidence that the board can check, or `any_release` changes meaning.

## Corrections from the paper review (item 17a) and the Sessions records D-032 to D-045 (item 25)

Entries 65 to 68 close the findings for the design specification of `REVIEW-17a.md`. Findings 4 and 7 correct a definition and a rounded figure: DESIGN §11.2 and §11.3 take them without an entry, and no rule changes. Finding 6 is the fixture of item 11, and finding 8 is closed on `main`. Entry 69 takes the Veritee decision records D-032 to D-045 of branch `committee-sessions-seald`. Entry 51 stays as written.

65. **Settlement safety needs `|C| ≤ f`; the host chain keeps one spend by the pinned input against any coalition.**
   - Context and problem: C11 named the adversary "any". Its argument read "two sets of `q` signers share an honest node". Two sets of `q` signers share `2q − n` nodes: 3 at `n = 9` and 7 at `n = 17`, which is `f + 1` and `2f + 1`. They share an honest node only while the coalition is smaller than that overlap, and the board that orders the leaves is safe only for `|C| ≤ f`. Review finding 17a-1 (paper PA1).
   - Drivers: C11 (one spend per record state), RQ-054 (one outcome per `auth`), AU-024, entry 47 (the pinned input), entry 52 (no committee Midnight write per request).
   - Considered options:
     - (a) State C11 in two parts: on the host chain against any coalition, by the pinned input or nonce; for settlement against `|C| ≤ f`. A larger coalition can sign two outcomes for one authorization, and the pinned input still lets at most one spend confirm.
     - (b) Settle each request on Midnight with a per-request transaction that the contract orders. Rejected: entry 52 and the owner's rule of no per-event Midnight writes.
     - (c) Raise `q` so that two quorums share `t` nodes. Rejected: `q > n − f` loses liveness with `f` silent nodes.
   - Outcome: (a). DESIGN §5.6 and the C11 row state the count `2q − n ≥ f + 1` and both parts. §9.2 keeps the host-chain part of C11 in every row and the settlement part while at most `f` enclaves are broken. RQ-054 cites this entry; no requirement statement changes. Authority: lead decision under owner delegation, 2026-11-15 (item 17a).
   - Consequences:
     - Good: C11 names the bound that its argument proves.
     - Bad: with `|C| > f` the settlement record can carry two outcomes for one `auth`, and a wallet that reads the wrong one waits on a pinned input that is already spent.
     - Neutral: no rule changes.
   - Confirmation:
     - outcome, arithmetic: `2·6 − 9 = 3 = f + 1` and `2·12 − 17 = 7 = 2f + 1`.
     - outcome, Quint model (item 26): `C11_OneAuthPerNullifier` and `C11_ReleasedNeverUnspent` hold on the design instances with `|C| ≤ f`; the fork instances `sl_*_b*` with `|C| > f` are the S1 runs.
   - Revisit when: the board gains a safety bound above `f`, or settlement moves to Midnight per request.

66. **C2 holds against `|C| ≤ f` in non-TEE mode without a slot anchor.**
   - Context and problem: C1 and C2 named the adversary `|C| < q`. C2 also needs `x_f` secret: a coalition that knows `x_f` and its own shards knows the full key of every address whose other shards it holds. In non-TEE mode without `slot_anchor`, a coalition of `f < |C| < t` forks the board and solves for `x_f` from three committee halves on one slot (finding S1, entry 42). At `n = 17` that is `|C| = 10`. C1 does not depend on `x_f`. Review finding 17a-2 (paper PA2).
   - Drivers: C1, C2, C12, entry 42 (S1), SH-011, O32.
   - Considered options:
     - (a) State the bound: C2 holds for `|C| < q`, and in non-TEE mode without a slot anchor for `|C| ≤ f`.
     - (b) Make `slot_anchor` mandatory in non-TEE mode. Rejected: it adds one checkpoint interval plus Midnight finality to every release (§11.2), and entry 42 keeps it a committee option.
   - Outcome: (a). The DESIGN C2 row and the note of SH-011 state it. No requirement statement changes. Authority: lead decision under owner delegation, 2026-11-15 (item 17a).
   - Consequences:
     - Good: the claims table matches the bound of C12 and C5 in the same mode.
     - Bad: a non-TEE committee without anchors protects birth against `f` corrupt nodes, not `q − 1`.
     - Neutral: TEE mode and committees with `slot_anchor` keep `|C| < q`.
   - Confirmation:
     - outcome, vectors: `design/enhancement/vectors/quint_counterexamples.py` case S1 recovers `x_f` at `b = 6`, `n = 9`.
   - Revisit when: O32 settles the slot anchor, or non-TEE mode is dropped.

67. **A network-created shard is born unacknowledged; the holder acknowledges with a proof of possession under `X_u`, and a payer funds only an acknowledged address.**
   - Context and problem: for an offline holder the creator sets `X_u = U + Hq_st(e_c·U)·G` and proves `δ` for `X_u − U`. The birth check verifies `pop_U` and that proof. Neither binds the ciphertext of `E_c` that the asset record carries. A creator that puts another point `E_c'` there passes the birth check, and the holder derives `x_u' = u + Hq_st(u·E_c')` with `x_u'·G ≠ X_u`. Nobody knows the shard, and coins paid to the address lock. C1 claimed that the holder knows the discrete log of its shard. Review finding 17a-3 (paper PA3).
   - Drivers: C1, C2, SH-008, SH-009, SH-011, DESIGN §5.3 item 5 (no curve arithmetic in the authorization circuit), entry 52 (no committee Midnight write per request).
   - Considered options:
     - (a) A proof at birth that the ciphertext of the record decrypts to the `e_c` behind `δ`. It needs `e_c·U`, `Hq_st`, `δ·G` and a verifiable decryption on secp256k1 inside a circuit. Rejected: DESIGN keeps curve arithmetic out of circuits, and the birth check runs at the nodes, where no Midnight proof system runs.
     - (b) A holder acknowledgement. The record is born with `acked = false`. The holder, once online, derives `x_u`, checks `x_u·G = X_u`, and sends an `ACK` envelope (request type 0x07) with `pop_u` under `X_u`. `q` nodes sign `ACK_OK`, the holder's `acknowledge` call sets `acked = true`, and a payer wallet pays only to an acknowledged address.
     - (c) The creator proves the encryption by showing `e_c` to the nodes. Rejected: `e_c` and `U` give `x_u − u`, so the nodes would learn a relation of the holder's keys.
   - Outcome: (b). The acknowledgement reuses the birth data and the proof of possession of §3.1 step 3, so an extractor obtains `x_u`, and C1 holds for an acknowledged shard. New requirements SH-030 to SH-037; SH-008 and SH-011 cite this entry. DESIGN §3.1, §4.6, §5.7, §6.4 item 13, §11.6, C1. Authority: lead decision under owner delegation, 2026-11-15 (item 17a).
   - Consequences:
     - Good: a payer never funds an address whose holder cannot sign, and C1 covers network-created shards.
     - Bad: an address of an offline holder takes payments only after the holder comes online once. A creator that funds it earlier carries the risk.
     - Bad: one more user Midnight transaction per network-created address (§11.6), and one more envelope on the board.
     - Neutral: the acknowledgement shows when the holder came online, and in non-TEE mode nodes link it to the birth by `X` (§6.4 item 13).
   - Confirmation:
     - outcome, vectors: `quint_counterexamples.py` case PA3. With a bad `E_c` both birth proofs verify and the point of the holder differs from `X_u`; the old rule funds a locked address and the new rule funds nothing. With the honest `E_c` the holder acknowledges.
     - outcome, Quint model `formal/quint/splitline_birth.qnt`: `bl_design` holds `C1_FundedOnlyDerivable` and `C1_AckedOnlyDerivable`; the mutants `bm_fund_on_final` and `bm_ack_no_pop` break them; scripted runs `bt_*`.
     - conformance, Lean oracle (LOOP item 13): SH-030 to SH-037 as transitions and refusals. Planned.
   - Revisit when: a zero-knowledge birth proof (O8) can prove the encryption of `E_c`, or a host chain lets a holder refuse a payment.

68. **Opening checks read only the envelope; the authorization match and precedence are admission checks that run once the authorization is in force.**
   - Context and problem: DESIGN §4.7 listed precedence (item 3) and the authorization in force with its match to `hd` and `tkc` (item 5) among the checks after the header opens. A header opens while its authorization finalizes (C6, changed hypothesis 1), and ECDSA precedence needs an authorization in force (entry 54). EN-012 treated a `tkc` mismatch as a malformed header at opening, and SL-016 posted SLOT_TAKEN at opening. A node could then void a request before its authorization existed. Review finding 17a-5 (paper PG1).
   - Drivers: C6, C13, EN-012, RQ-013, RQ-014, RQ-023, RQ-025, SL-005, SL-016, entry 54, entry 63.
   - Considered options:
     - (a) Split §4.7. Items 1 to 4 and 6 are opening checks that read only the envelope: decryption, structure, distinct points, the TEE recomputation and the contribution frames. Item 5 is the admission check, run once the authorization is in force: `auth` commits to `hd` and `tkc` (AUTH_REFUSED), and the request has precedence on every slot it names (SLOT_TAKEN). A header whose authorization never comes into force lapses by SL-005.
     - (b) Hold the header closed until the authorization is in force. Rejected: it adds `F_M` to the open, and §11.2 overlaps the two.
     - (c) Keep both checks at opening and let them wait for finality. Rejected: that is (a) without a stated state for the waiting header.
   - Outcome: (a). EN-012 keeps only the missing `ic` or `r_tkc`. RQ-025 takes the `tkc` and `hd` match once the authorization is in force. SL-016 posts SLOT_TAKEN only while the authorization of the request is in force. RQ-023 names both admission checks. DESIGN §4.7, §5.2 item 4, §5.4 items 1 and 2. Authority: lead decision under owner delegation, 2026-11-15 (item 17a).
   - Consequences:
     - Good: no node voids a request by a check that needs an authorization it does not have yet, and the paper and DESIGN state one order.
     - Bad: a header with a wrong `tkc` stays open until its authorization finalizes, and its precedence holds its slots until then or until the lapse at its ordering height plus `Δ_c`.
     - Neutral: the ADMIT vote already required the authorization in force, so the normal path does not change.
   - Confirmation:
     - outcome, Quint model `formal/quint/splitline.qnt`: rule `admissionInForce` guards `doVoidSlotTaken`, and invariant `C13_SlotTakenOnlyInForce` is in `AllInvariants`. `pg1_design` runs `pg1OpenVoidHolds` and `pg1OpenVoidRefusedHolds`; the mutant `pg1_m_open` breaks the invariant in `pg1OpenVoidBroken`. `g5VoidHolds` now ends the unauthorized envelope LAPSED.
     - conformance, prototype: `impl/src/split/state.rs` `vote_ready` checks `in_force` before `precedence`. `impl/tests/quint_split_replay.rs` replays `pg1_design__pg1OpenVoidHolds` and refuses the step of `pg1_m_open__pg1OpenVoidBroken`.
     - conformance, Lean oracle (LOOP item 13): EN-012, RQ-025 and SL-016 with the in-force condition. Planned.
   - Revisit when: the board can show an authorization in force before ordering, or the TEE recomputation moves to admission.

69. **The split-line mapping takes the Sessions records D-032 to D-045.**
   - Context and problem: entry 51 maps the committee state onto seald Sessions with the records D-001 to D-031 of branch `committee-sessions`. Branch `committee-sessions-seald` adds D-032 to D-045 and the requirements SS-142 to SS-147. Some of them change contract rules and node behavior that DESIGN states: the pending floor and the jump on a moved restart marker (D-039), the running-node burn (D-040), the lost `RestoreDone` (D-037), the statement encoding (D-041) and the later unverified ledger view (D-044). Item 25 asks DESIGN §2.2, §4.5, §7.4, §7.8, §7.11, C16 and entry 51 to match `design.md` of `add-seald-sessions`.
   - Drivers: C12, C16, CP-009, CP-011, CP-016, CP-019, CP-021, CP-022, CP-039; Sessions goal G3; the owner's rule of no per-event Midnight writes.
   - Considered options:
     - (a) Take each record into DESIGN and the checkpoint spec where it changes state or a size that DESIGN states, and list the others as taken as they stand.
     - (b) Rewrite entry 51. Rejected: earlier entries stay as written (LOOP rules).
   - Outcome: (a). The bindings:
     1. **Roots per checkpoint and the slot anchor** (D-032, D-033: SS-070 to SS-073, SS-139). Midnight takes one root per seat per checkpoint. A slot-anchor binding is the entry `(nf, e)`: the slot nullifier under `k_nf` and the hidden digest. The enclaves derive `k_nf` once at genesis, and a rekey carries it. DESIGN §2.2, §4.1, §7.7, §7.13; CP-016.
     2. **Pending fields and the batch bind** (D-034, D-035: SS-063 to SS-066, SS-140, SS-141). DESIGN takes them as they stand (§4.1, §7.7).
     3. **Rekey of a closed session** (D-036: SS-143, SS-144). DESIGN §7.8.
     4. **Lost `RestoreDone`** (D-037: SS-145). The node keeps the statement in RAM and appends it again. DESIGN §7.4, §7.11; CP-042.
     5. **Rollback before the share install** (D-038). A limit, no rule. DESIGN §7.11 item 2.
     6. **Pending floor and marker jump** (D-039: SS-146, SS-147). The contract refuses a checkpoint that lowers `pending_min`, and a checkpoint that moves `restart_seq` jumps the window as the first checkpoint after a restart does. The marker moves at the first checkpoint that carries, or follows a checkpoint that carries, a qualifying `RestoreDone` (SS-121). The loss bound of C16 grows by one window per seat that syncs after a rollback of every disk. DESIGN §7.11, §7.13 ("Why `pending_min` is enough" item 6), C16; CP-011, CP-039, CP-040, CP-041.
     7. **Running-node burn** (D-040: SS-113, SS-114, SS-133). A running node burns its open sessions in RAM, and the next seal records the burn. An account pool burns once per restart generation. DESIGN §7.11; CP-021, CP-022.
     8. **Statement encoding** (D-041). `RestoreDone` is 117 bytes with a u32 node index. DESIGN §7.13 and §11.6: 117 B per seat, at most 1,053 B at `n = 9` and 1,989 B at `n = 17`; CP-016.
     9. **Later unverified ledger view** (D-044: SS-066, SS-106, SS-137). The node keeps the last verified view. DESIGN §7.11; CP-043.
     10. **Taken as they stand**, with no DESIGN text: the u32 share length with its maximum of 524,288 bytes (D-042: SS-087), the u64 versions that refuse at exhaustion (D-043), and `bad_request` before `fenced` and `not_ready` for a malformed batch item (D-045: SS-081 to SS-083, SS-141).
     11. **Account-pool burn without a slot list** (prototype finding PR4). A node finds its account pools among its sessions: the session `keys` maps each ECDSA address to its pool id, and its local records and witness sync entries name every session of the seat. The burn takes every slot of each pool, so it needs no list of named slots. DESIGN §7.11; CP-021.
     Authority: lead decision under owner delegation, 2026-11-15 (item 25). It takes the Veritee lead decisions D-032 to D-045, made under owner AFK delegation.
   - Consequences:
     - Good: DESIGN, the checkpoint spec and `design.md` state the same contract rules, sizes and burns.
     - Good: a restart in which the seats sync one at a time after a rollback of every disk reuses no slot (D-039 schedules C-01 and C-02).
     - Bad: such a restart retires one window per syncing seat.
     - Neutral: the contract reads two more fields of the previous checkpoint per pool (`pending_min`) and per checkpoint (`restart_seq`).
   - Confirmation:
     - outcome, Quint model (Veritee): the regression schedules C-01 and C-02 of D-039 and C-04, C-05, C-11 and C-12 of D-040 in the Sessions model.
     - outcome, Quint model `design/enhancement/quint/batched_checkpoint.qnt`: the contract rule refuses a lower `pending_min`, and `C13_honestCheckpointLands` checks that no honest checkpoint is refused (`bc_design`).
     - outcome, Quint model `formal/quint/splitline_pools.qnt`: the mutant `acctBurnAll = false` (burn only the slots that the readable board named) breaks `C16_NoSlotTwice` in `pt_acct_named` `accountBurnBroken`; `pt_seald` `accountBurnHolds` holds.
     - conformance, Lean oracle (LOOP item 13): CP-011, CP-021, CP-022 and CP-039 to CP-043. Planned.
   - Revisit when: Veritee adds records after D-045, O32 settles the slot anchor, or the checkpoint gains per-seat fields.
## Rulings from the replay of the Quint traces through the Lean oracle (item 14)

The replay of the item 14 Quint traces through the Lean oracle found five classes of disagreement. The lead ruled each one as a reading of the specs. Rulings A (RQ-046: expiry is urgent), B (RQ-020 refuses a frame above `exp_c` in every phase, ORDERED included) and E (a restart does not end again a request whose leaf Midnight holds, entry 58) change no spec text. Rulings C and D add one sentence each, recorded here. The lead renumbers this entry at merge.

70. **A frame for an OPENED or ADMITTED target is refused, and a restart that loses the board tail keeps `any_release` and `released`.**
   - Context and problem: RQ-021 holds a frame while its target is POSTED or ORDERED, and RQ-018 attaches a frame while its target is COLLECTING. No sentence says what happens to a frame whose target is OPENED or ADMITTED, so the spec-only Quint model held such frames and its replay through the Lean oracle disagreed. The Quint model also let a whole-committee restart that loses the board tail after the latest landed checkpoint clear `any_release` and `released`, while no sentence of the specs clears them.
   - Drivers: C11 (one spend per record state), C20 (a stalled request releases nothing), RQ-037 (the only rule that sets `any_release`), entry 53 (a restart end settles FINAL or RELEASED), entry 58 (a leaf that Midnight holds is settled), RQ-020.
   - Considered options:
     - (a) New RQ-075: a frame ordered while its target has `phase` OPENED or ADMITTED is refused with the code `late_contribution`. New RQ-076: a restart that loses the board entries after the latest landed checkpoint keeps `any_release` and every `released[g]`.
     - (b) Hold a frame for an OPENED target until the OPENED vote commits. Rejected: RQ-021 names only POSTED and ORDERED (lead ruling C).
     - (c) Let the restart clear the release record of the lost tail. Rejected: no sentence clears `any_release`, and entry 53 settles a restart end RELEASED because release evidence can lie in the lost tail.
   - Decision: (a). `any_release` is monotone: once set, it stays set. Authority: lead rulings C and D on the item 14 replay, 2026-11-15.
   - Consequences:
     - Good: every frame event has one result in every phase, and the oracle and the model read the same refusal code.
     - Good: C11 no longer depends on which board entries a restart reads; a released request settles RELEASED or FINAL.
     - Bad: an actor whose frame reaches the board while the OPENED vote is pending must post it again after the target is COLLECTING.
     - Neutral: no new field and no new code; `late_contribution` already exists (RQ-020).
   - Confirmation:
     - outcome, Quint model `formal/quint-spec`: the `frame` action holds only for a POSTED target or an ORDERED target at a height at most `exp_c`, the refusal tier refuses an OPENED or ADMITTED target with `late_contribution`, the restart keeps `any_release` and `released`, and `inv_RQ076_C11_releaseMonotone` is in the gate.
     - conformance, Lean oracle (LOOP item 13): RQ-075 as a refusal and RQ-076 as a restart transition. Planned.
   - Revisit when: frames carry the header hash that the OPENED vote commits, or the restart reads more than one checkpoint.

## Fix for the Quint finding F7 (item 14c)

Entry 71 closes finding F7 of `formal/quint-spec/FINDINGS.md`, which the revision 6 run of the spec-only Quint model found.

71. **The pending list of a checkpoint holds no index below the `pending_min` of the previous landed checkpoint.**
   - Context and problem: CP-014 signed `pending_root` over every committee slot that a live request holds on the board, and SL-004 gives precedence on an UNNAMED slot to any header that opens, with no window clause. CP-040 (entry 69) refuses a checkpoint whose `pending_min` falls below the previous landed one. Finding F7 (schedule `cp040PendingMinLoweredBlocked1Test` of revision 6): request 1 reserves committee slot 2 and checkpoint 1 lands with `h = 2` and `pending_min = 2`; request 2, never authorized, names the UNNAMED slot 1 and its header opens, so SL-004 gives it precedence; the honest checkpoint now has `pending_min = 1`, and CP-040 refuses it. The block holds until SL-013 voids request 2 with `f + 1` SLOT_TAKEN posts or SL-010 burns slot 1 at its lapse. Until then no checkpoint and no `settle_root` lands, and a spammer can post such envelopes again and again. This is a liveness defect: no slot binds twice.
   - Drivers: C13 (liveness: a valid, authorized envelope reaches an end, which needs landed checkpoints), C15 (recovery opens after `Δ_rec` without a checkpoint), C16 (the restart burn reads only `h`, `pending_min` and `B` of a landed checkpoint), CP-005 (one Midnight write per checkpoint), CP-014, CP-040, SL-004, SL-013, entry 69.
   - Considered options:
     - (a) CP-014 lists only the slots at or above the `pending_min` of the previous landed checkpoint for that pool. A first checkpoint, or a pool that the previous landed checkpoint does not list, has no floor and lists every slot that a live request holds. SL-004 stays as it is.
     - (b) SL-004 gives no precedence on an index below the window of the latest landed checkpoint. Not chosen: it changes the slot ledger for every header, and a node then needs the landed checkpoint at opening to decide precedence, while (a) changes one sentence and closes the block at the checkpoint where it arises.
     - (c) Keep both rules and let CP-040 ignore a lower `pending_min` that only such precedence causes. Rejected: the contract cannot see why the floor fell, and CP-040 exists to refuse exactly such a checkpoint from rolled-back disks.
   - Outcome: (a). An index below the previous floor never gets an honest vote and ends its request VOID with SLOT_TAKEN (SL-013), and seald refuses it at `slot_bind`, so leaving it out of the list loses no slot that can bind. The honest `pending_min` is then never below the previous floor: a list entry is at or above it, and an empty list gives `h + 1`, which is above it because the previous checkpoint had `pending_min ≤ h + 1` (CP-008) and `h` does not fall (CP-007). CP-040 refuses only a dishonest or rolled-back checkpoint again. DESIGN §4.1 (reservation window) and §7.13 (contract rules); CP-014 with a new scenario; the note of CP-040. Authority: owner ruling, 2026-11-15 (item 14c finding F7, fix (a)).
   - Consequences:
     - Good: an envelope from anyone can no longer stop every checkpoint, and every `settle_root` lands at its interval again.
     - Good: the change is one clause of CP-014. SL-004, SL-010, SL-013 and the contract rules stay as they are.
     - Bad: the signer reads the previous landed `pending_min` of each pool to build the list.
     - Neutral: a request that holds an index below the previous floor still holds its precedence until SL-013 or SL-010 ends it; its slot is not listed and never binds.
   - Confirmation:
     - outcome, Quint model `formal/quint-spec`: `f7SpamPrecedenceLandsTest` runs the F7 schedule and lands the checkpoint with `pending_min = 2`; `inv_CP014_CP040_honestFloorKept` is in the gate; mutant `pending_unwindowed` restores the old listing and breaks it on the same schedule.
     - conformance, Lean oracle `formal/lean-split/checkpoint`: `signPending` reads the previous landed `pending_min` of the pool; the pin `pin_pending_floor` runs the F7 scenario; the Spec mutants that drop the floor or make it strict fail the build at the `cp014_pmin_floor` proof.
   - Revisit when: SL-004 takes a window clause, or the checkpoint drops `pending_min`.

## Enhancements from the literature survey (item 40)

Entries 72 to 78 take the proposals marked ADOPT in `research/literature-2026-11/ENHANCEMENTS.md` (E1, E2, E3, E5, E6, E8, E9). Each entry is a lead pick, for owner confirmation. Entry 72 changes the protocol. Entries 73 to 77 change the statements of claims and open items, and no message or check. Entry 78 adds a test.

72. **The commitment list starts with the initiator's leaf id.** Lead pick, for owner confirmation.
   - Context and problem: DESIGN §4.2 item 3 built `CL` from `R_0`, the pool pairs of the actors of `S' = S ∖ {a_0}` and the committee slot. The initiator's leaf id was not in the list. A weight `λ_a` depends on the whole signing set (§2.4, SH-004): in a 2-of-3 group member 1 has weight 2 beside member 2 and 3/2 beside member 3. Two requests that differ only in the initiator therefore had one `CL` and one `pm`, so member 1 had one `ρ_a`, one `R` and one `c` under two weights. The adversary chose the weight after the hash fixed the challenge. Two answers on the pair gave `x_a = (s_a − s_a')/(c̃·(λ_a − λ_a'))`, so the only rule between the adversary and the leaf secret was that an actor answers a pair once (SH-015). Bellare, Crites, Komlo, Maller, Tessaro and Zhu (CRYPTO 2022) state the condition for the weighted Schnorr assumption behind FROST2: the weights "(in addition to the nonces) must be included as input" of the binding hash "or else there is an attack". Finding E1 of `tests/quint-regressions/splitline/COUNTEREXAMPLES.md` reproduces the case on `impl/`: one binding factor and one ticket under two weights, and the leaf secret from the answers of one pool and of a copy of it.
   - Drivers: C19 (no concurrent-session forgery against an actor), C17, C18, O20 (the reduction for pool actors), O14, O18, SH-004 (the weight follows from the signing set alone), SH-015, SH-021, SH-022.
   - Considered options:
     - (a) `CL = leaf_0 ‖ R_0 ‖ …`, with `leaf_0` the initiator's leaf id. `CL` then names every leaf of `S`, so it fixes `S` and every weight.
     - (b) Hash the weight `λ_a` itself into `ρ_a`. Not chosen: it fixes the weight of one actor and leaves the set open, and (a) binds the same value with no new encoding of a field element.
     - (c) Hash the whole header, which names `S`. Not chosen: every `ρ_a` would then depend on header fields that do not bear on the signature, and a re-post with one changed header field would change every binding factor.
     - (d) Keep `CL` and rely on the one-answer rule. Rejected: the binding factor then misses the stated input condition of the assumption that O20 reduces to, and a pool restored from a backup answers a pair again.
   - Outcome: (a). DESIGN §4.2 item 3 and its binding paragraph, row C19 and row O20. New requirement SH-038. The prototype (`impl/src/split/schnorr.rs`, `Request::transcript`) hashes the initiator's leaf id before `R_0` for BIP340 and Ed25519. ECDSA has no `CL`: a slot is bound to one leaf set (§3.6 step 7). Lead pick, for owner confirmation.
   - Consequences:
     - Good: one `CL` fixes the weight of every actor, and no pair of an honest actor is bound to two weights. The game of O20 meets the input condition of the published weighted assumption.
     - Good: no message changes. The header already names `S`, and the list gains one leaf id as hash input per half.
     - Bad: every binding factor, nonce point, challenge and ticket of a request with other actors changes, so vectors and recorded tickets made with the old list do not verify. The single-user form has no `ρ_a` and does not change.
     - Neutral: a pool restored from a copy still answers a pair twice. With (a) the two answers stand on two nonces, and three answers on one pair still give the pair. The one-answer rule (SH-015) stays in force.
   - Confirmation:
     - counterexample, prototype: `impl/tests/e1_initiator_leaf_counterexample.rs`. On the code before the fix the two `counterexample` tests passed and the two `regression` tests failed (`tests/quint-regressions/splitline/e1_before_fix.txt`). On the fixed code the six tests pass.
     - outcome, Quint model `formal/quint/splitline_binding.qnt`: `C19_BindingFixesWeight` and `C19_OneNonceOneWeight` hold on `dl_design` and `dl_design_rollback`. The mutant `dm_no_initiator` breaks the first, and `dm_no_initiator_rollback` breaks the second. The tests `e1_*_quint_binding_traces_replay` replay the scripted traces on the prototype.
     - conformance, Lean oracle `formal/lean-split/shard-holders`: `clActors`, the theorems `sh038_cl_fixes_weight` and `sh038_cl_fixes_members`, the pin `pin_two_initiators`, and the Spec mutant that drops the initiator, which fails the build at `sh038_cl_fixes_members`.
     - vectors: `design/enhancement/vectors/check.py` case (e), and the lists of `check.py` and `ed.py`.
   - Revisit when: the proof of O20 names another binding input, or a charter lets a leaf appear in two positions of one signing set.

73. **C5 and O6 name TS-SUF-2 with one-time slots, and O6 lists four extensions.** Lead pick, for owner confirmation.
   - Context and problem: row O6 asked for "a reduction to AOMDL in the ROM" with a signing oracle of one query per committee slot. Row C5 called the argument "a one-more-DL argument over nonce slots, in the style of the FROST proofs". Neither named a security notion, so the obligation had no stated end. Bellare et al. (CRYPTO 2022) define the hierarchy TS-UF-0 to TS-SUF-4. Theorem 3 proves that FROST2 is TS-SUF-2 under OMDL in the random oracle model for static corruption below `t`. Their §4.4 shows that a binding factor shared by all signers does not reach TS-UF-3. The committee's `ρ` is one factor for the whole committee.
   - Drivers: C5, C12, O6, O27, O30, SH-028.
   - Considered options:
     - (a) State C5 as TS-SUF-2 with one-time slots under OMDL, and list in O6 what the published proof lacks.
     - (b) Claim TS-UF-3 or higher. Rejected: the published attack on a shared binding factor applies to `ρ`.
     - (c) Give each node its own binding factor, as FROST1 does, to reach TS-SUF-3. Not chosen: the ticket and the node's partial check would then carry `n` factors. The design needs level 2 only, because the board anchor selects the answered ticket and the adversary does not.
   - Outcome: (a). Rows C5 and O6, and the C5 line of §9.3. The up-to-`K` candidate tickets on a slot need no new oracle: in the published game the adversary hashes any number of requests on one token and chooses the answered one, and the anchor's choice is weaker. O6 lists four extensions: a Shamir-dealt slot `(d_ℓ, e_ℓ)` with one `ρ`, a node that takes `c̃` from the ticket, the factor `c̃ = g·c` with the sign `σ`, and the public additive part `x_A`. The assumption of the target is OMDL, as in Theorem 3. A proof that needs AOMDL for an extension states it. Lead pick, for owner confirmation.
   - Consequences:
     - Good: O6 is four named extensions of a published proof.
     - Good: the design claims no notion that a shared `ρ` cannot meet.
     - Neutral: no message, check or parameter changes.
     - Bad: the proof bodies of the lemmas behind Theorem 3 are in the full version of the paper (ePrint 2022/833), which is not among the works read for the survey. The proof of O6 reads it first.
   - Confirmation: DESIGN rows C5 and O6 name the notion, the theorem and the four extensions. O6 is done when the written proof exists.
   - Revisit when: the committee's binding factor becomes per node, or the static scope of §9 changes.

74. **The reshare adversary is a dual threshold.** Lead pick, for owner confirmation.
   - Context and problem: claim C14 was stated for `|C_old| ≤ f` and `|C_new| ≤ f'`. Claim C5 needs `x_f` hidden from `t − 1 = 6` nodes. The reshare claim did not say which of the two secrecy bounds it keeps, so C5 had no stated bound across an epoch change. Two published theorems cover the model in which `f` nodes misbehave and the shares of up to `t − 1` nodes in total are exposed. They are Theorem 1 of Yurek, Xiang, Xia and Miller (USENIX Security 2023) and Theorem 1 of Das, Xiang, Kokoris-Kogias and Ren (USENIX Security 2023). Both are asynchronous, and both are for other commitment schemes than the Feldman dealings of §8.1.
   - Drivers: C14, C15, C16, C5, O5.
   - Considered options:
     - (a) State C14 and O5 against `f` Byzantine nodes plus the exposed shares of up to `t − 1 − f` further nodes, in each committee.
     - (b) Keep `|C| ≤ f` for secrecy. Rejected: the rotation claim is then weaker than the secrecy that C5 uses, and a coalition of three old nodes is outside every claim.
     - (c) State secrecy against `t − 1` Byzantine nodes. Rejected: with 6 Byzantine nodes of 9 no qualified set of `t` honest dealers exists, so HANDOVER has no liveness, and no published reshare proves that case.
   - Outcome: (a). DESIGN §8 (the adversary paragraph), row C14 and row O5. At `n = 9` and `f = 2` the model is 2 Byzantine nodes and 4 exposed ones, and the sharing degree 6 meets `d ≤ n − f − 1`. Lead pick, for owner confirmation.
   - Consequences:
     - Good: O5 names an adversary for which asynchronous theorems exist, and C14 keeps the secrecy bound of C5 across epochs.
     - Neutral: the mechanism of §8.1 is unchanged.
     - Bad: the two theorems are for other commitment schemes and their own protocols. The proof for the Feldman dealings and the complaint window of §8.1 is still to write.
   - Confirmation: DESIGN §8 and rows C14 and O5 carry the same statement. O5 is done when the proof exists.
   - Revisit when: the publicly verifiable reshare of survey entry E4 is adopted, or `t` is no longer `n − f`.

75. **O1 asks for identifiable abort with exclusion, and names three missing pieces.** Lead pick, for owner confirmation.
   - Context and problem: row O1 asked for `F_presig` "secure with `f` Byzantine nodes" and named DKLs23, CGGMP21 presigning and a 2PC-MPC emulation as protocols. Guaranteed output of a presignature with 6 corrupt nodes of 9 is in no published theorem. Three protocols have a theorem that covers 7 of 9 with 6 corrupt, and each aborts under one misbehaving node (DKLs23 Theorem 4.1, Trout++ Theorem 7, Lyu et al. Theorem 1). ARES states that robustness needs a broadcast channel and `n ≥ 2t + 1`. CGGMP21 has identifiable abort, the line form and the partial check in base `R` for n-of-n signers, with presignatures fixed to the signing set, and it outputs no threshold shares. Trout++ and Lyu et al. re-randomize `R` at signing time, which a slot point fixed at birth excludes.
   - Drivers: C5 (ECDSA), C13 (liveness), O1, O19, O11.
   - Considered options:
     - (a) `F_presig` gives identifiable abort. A session that aborts names a node, the board excludes that node from the next attempt, and with at most `f` exclusions `t` nodes remain.
     - (b) Keep the demand for guaranteed output. Rejected: no published protocol gives it at `t = n − f`.
     - (c) Accept an abort without a named node. Rejected: one corrupt node then stops every birth and every refill.
   - Outcome: (a). DESIGN §3.6 (`F_presig`) and row O1. The row lists three pieces that no published protocol has: degree-`(t − 1)` Shamir shares of `φ = k_f⁻¹` from a dishonest-majority multiplication that opens the product of `k_f` and a mask, committed shares of `ψ = k_f⁻¹·x_f` where the product of the mask and `x_f` cannot be opened, and a proof for a slot point used long after its birth. §3.6 names CGGMP21 presigning as the source of the base-`R` check. It does not name it as a protocol that realizes `F_presig`. Lead pick, for owner confirmation.
   - Consequences:
     - Good: the liveness that O1 asks for is the liveness that published protocols provide, and the gap is three proof tasks.
     - Bad: a retry costs one more session per named node, and a birth with `f` corrupt nodes takes up to `f + 1` attempts.
     - Neutral: the board rule that excludes a named node from a session belongs to the protocol that closes O1 and O19. No model and no prototype has it yet.
   - Confirmation: DESIGN §3.6 and row O1. O1 is done when a protocol with a written proof has the three pieces.
   - Revisit when: a published protocol gives guaranteed output at `t = n − f`, or the slot point may be re-randomized at signing.

76. **A detected cheat in one multiplication ends every multiplication of the session.** Lead pick, for owner confirmation.
   - Context and problem: §3.6 runs `3·n_A·(n_A − 1)/2 + 3·n_A·n` instances of `F_mul` per slot, and row O2 asked only for a malicious-secure two-party multiplication. A multiplication of this kind can leak one bit of an input when a cheat is detected. The Coinbase cb-mpc secure-usage guide states that its two-party signing variant is secure only if on detection "all executions with that key are halted". DKLs23 (Theorem 6.1) and CGGMP21 obtain input consistency across instances only by binding each input to a public point in base `G`. ARES (Theorem 5) gives a multiplication with public checking that names the cheater.
   - Drivers: C5 (ECDSA), C17, O2, O19, O33.
   - Considered options:
     - (a) A failed check in any `F_mul` instance of a birth or refill session ends every instance of that session for that address, burns the session's slots and names the party. O2 requires input consistency by a public point per input and names the ARES multiplication.
     - (b) Drop only the slot of the failed instance, as step 6 of §3.6 does for a failed share. Rejected for `F_mul`: the cheater repeats the attempt on the next slot of the same session and collects one bit of the same input each time.
     - (c) Halt every later session of the address, which is the rule of the cb-mpc guide for a key. Not chosen: one cheat by one party would then lock the funds of the others.
   - Outcome: (a). DESIGN §3.6 (the rule after `F_mul`) and row O2. Lead pick, for owner confirmation.
   - Consequences:
     - Good: a cheat that leaks one bit per attempt gets one attempt per session.
     - Good: O2 and O19 share one mechanism, the publicly checked multiplication.
     - Bad: one detected cheat costs the whole session. The ARES multiplication needs a class group and a broadcast, and the board is the broadcast.
     - Bad: the same shard `x'_p` enters every birth and refill session of the address, so a cheater that accepts being named still gets one bit per session. The halt covers the session and not the key.
     - Neutral: this entry does not set how many sessions a named party may fail before the charter replaces it.
   - Confirmation: DESIGN §3.6 and row O2. The rule gets its test when the session of O2 and O19 is built.
   - Revisit when: the chosen multiplication leaks nothing on a detected cheat, or O19 fixes another blame mechanism.

77. **The proof of O26 follows the batched-encryption template.** Lead pick, for owner confirmation.
   - Context and problem: row O26 asks for a written proof of Theorem D restated, with the sealed contribution, the complaints and the Chaum-Pedersen transcript. It did not say in which model the dealing proof `π` is extracted, and it did not state why a bad partial cannot change which variant is released. BEAT-MEV (USENIX Security 2025, Theorem 5.1 and §6) proves chosen-ciphertext security of batched threshold encryption from a simulation-extractable proof bound to the ciphertext, with public verification of decryption shares against selective opening.
   - Drivers: C8, C9, C18, O26.
   - Considered options:
     - (a) O26 follows that template, states whether `π` is extracted by rewinding in the random oracle model or in the algebraic group model, and states that the anchor is fixed before any body partial.
     - (b) Leave the model of extraction to the proof. Rejected: the two models give different theorems, and the choice decides whether C8, C9 and C18 hold in the random oracle model alone.
   - Outcome: (a). DESIGN row O26. Lead pick, for owner confirmation.
   - Consequences:
     - Good: the proof of C8, C9 and C18 has a published structure to follow.
     - Neutral: no message, check or parameter changes.
     - Bad: if rewinding does not give simulation extractability for `π`, the three claims take the algebraic group model as a hypothesis.
   - Confirmation: DESIGN row O26. O26 is done when the written proof exists and names its model.
   - Revisit when: the envelope's dealing proof or its threshold PRF changes.

78. **The suites hold a negative test for a ticket with an unbound challenge.** Lead pick, for owner confirmation.
   - Context and problem: a node is blind and takes `c̃` from the ticket (§4.2). The ticket check of §5.3 is the only rule that ties `c̃` to an admitted transaction. A signer that answers challenges which nothing binds to a message signs for an attacker, and a Wagner attack gets `K + 1` signatures from `K` sessions (bitcoin-dev thread "Blinded 2-party Musig2", July 2023). The prototype tested one flipped bit of a ticket's challenge, and no ticket whose `c̃` is the challenge of another transaction on the same `R`.
   - Drivers: C6, C5, O4, O18, O16.
   - Considered options:
     - (a) O18 and O4 gain a negative vector: a ticket whose `c̃` is not the challenge of an admitted transaction is refused, in the circuit and in the TEE path. The prototype holds the test for the path it has.
     - (b) Rely on the positive vectors. Rejected: they pass with the check removed.
   - Outcome: (a). DESIGN rows O18 and O4, and `impl/tests/e9_unbound_challenge.rs`. Lead pick, for owner confirmation.
   - Consequences:
     - Good: a regression guard on the one check that keeps a blind committee from signing for an attacker.
     - Neutral: the prototype has no ticket circuit (O4), and its reducer takes the TEE intent check as the flag `Header.valid`. Its test covers the recomputation of every ticket from the capsules, which the wallet, the actor (rule 1 of §4.2) and the combiner run. The node's own release check passes the forged ticket. The circuit suite and the TEE path take the same vector when they are built.
     - Neutral: the test forges one ticket per run. It does not run the Wagner search for `K + 1` signatures, which needs the same unchecked answer `K` times.
   - Confirmation: `e9_*_unchecked_ticket_signs_another_message` shows that the node's release check passes a ticket with another transaction's challenge, and that the result is a valid signature on that transaction. `e9_*_wagner_unbound_challenge_ticket_is_refused` puts the forged ticket at every position of a request header, and the recomputation refuses each one, for BIP340 and Ed25519.
   - Revisit when: the ticket circuit of O4 exists, or the ticket gains a blinded challenge.

## Committee handoff (item 41)

Entries 79 to 86 make the committee handoff a protocol operation (`HANDOFF.md`, DESIGN §8, requirements HO-001 to HO-063). Two owner rulings of 2026-11-16 bind them: "the user's shard should stay unchanged", and "the MPC protocol has to permit this action otherwise the keychains are static". Each entry is a lead pick, for owner confirmation, inside those rulings.

79. **The handoff is a mandatory protocol operation that Fenrir governance triggers, and an early ROTATE is queued.** Lead pick, for owner confirmation.
   - Context and problem: DESIGN §8 let "governance or the epoch schedule" post ROTATE and named no key set, no check and no rule for a ROTATE that arrives during another rotation, during a grace period or during a restart. Nothing stopped a charter or a mode from depending on a fixed committee. The owner ruled that the protocol must permit key rotation, or the keychains are static, and that governance is by rotated Fenrir operator keys.
   - Drivers: owner rulings of 2026-11-16 (handoff mandatory; the user's shard unchanged), the owner rule that governance is by rotated Fenrir operator keys, C13, C14, HO-001 to HO-012, HO-058.
   - Considered options:
     - (a) A ROTATE needs `q` signatures of the operator keys of the current roster, checked against the governance key set of the latest landed checkpoint. It names the target roster, parameters, source epoch and an emergency flag. A ROTATE whose preconditions do not hold is QUEUED and starts when they hold. No charter, profile, suite or mode takes part.
     - (b) Any committee node may post ROTATE. Rejected: one hostile node could rotate at will or flood the board with rotations.
     - (c) The Image Registry governance of 7 of 9 separate members approves rosters. Rejected: the owner rule names the rotated Fenrir operator keys, and an image approval is a different decision from a roster.
     - (d) A charter opts in to rotation. Rejected by the owner ruling: an address that cannot follow a handoff pins the keychain.
     - (e) Refuse a ROTATE whose preconditions fail. Not chosen: a refused ROTATE needs a new post, and a theorem that a handoff can start from every reachable state would be false.
   - Outcome: (a). `HANDOFF.md` §2.1, §3.1, §3.2; DESIGN §8.1 step 1; HO-001 to HO-012. The governance key set rotates with the roster at the activation record (entry 83). Lead pick, for owner confirmation.
   - Consequences:
     - Good: a handoff can start from every reachable state with no user action, and every address follows every handoff.
     - Good: `q` honest operators can always rotate, and `f` hostile operators cannot block or force a rotation.
     - Bad: `q` operators that collude can appoint a roster. That is the same coalition that already signs every checkpoint.
     - Neutral: a scheduled refresh needs the operators' signatures each epoch, collected on the board.
   - Confirmation: conformance, Lean oracle `formal/lean-split/handoff`: theorems `ho_start_from_any` and `ho058_no_user_action`; refusal codes `rotate_unauthorized` and `rotation_open`.
   - Revisit when: governance moves to another key set, or the roster is chosen by stake.

80. **The binding epoch owns its requests through grace, and a sweep carries the live ones.** Lead pick, for owner confirmation.
   - Context and problem: DESIGN §8 ended every in-flight request VOID at HANDOVER, and the owner re-posted it. That breaks the owner rule: the owner is online only to initiate a spend and to broadcast it. The user's sealed contributions fix `R` through the slot points and `ρ`, so the request cannot move to new slots, and `κ_0` was dealt to the keys of one epoch (MPC team reply to tyr, question 4, second half).
   - Drivers: owner rule (owner online only to initiate and broadcast), owner ruling (user shard unchanged), C3, C12, C13, DECISIONS 56, 59 and 60, HO-025 to HO-027, HO-036 to HO-044, HO-059.
   - Considered options:
     - (a) The epoch whose keys an envelope names owns the request until a sweep before its grace end. After the arming its members post their request entries as signed epoch posts. At the sweep, the live material (`κ_0`, `κ_c`, P0 lines, unreleased slots) of each live request is carried to the successor, which owns the request from the position where `n' − f'` new seats are ready for the sweep. From ROTATE to CLOSE every release is committed on the board first, and each carry lists the witnessed releases, so RELEASED settlement survives.
     - (b) Freeze admissions at a cut-over height and let the old committee finish the admitted requests. Not chosen: requests ordered but not yet admitted at the cut-over (authorization not final, collection open) still need either the old committee or a carry, and lagging wallets keep binding the old epoch.
     - (c) Switch every request to the new committee at the activation and carry the live material of every live request then. Rejected: the requests waiting for admission at that moment are about the request rate times the admission latency, at about 31 KB each at `n = 9`, a burst near the whole board bandwidth.
     - (d) VOID and re-post, as before. Rejected by the owner rule.
     - (e) Re-deal the request onto new-epoch slots. Rejected: the user's contribution fixes `R` and `c`, and a committee that signs without a new contribution breaks C3.
   - Outcome: (a). `HANDOFF.md` §2.3, §2.5, §4; DESIGN §8.2; HO-025 to HO-027, HO-036 to HO-044, HO-059. Lead pick, for owner confirmation.
   - Consequences:
     - Good: no live request needs a user action, and the user's sealed contributions stay valid, because `κ_0`, every slot and every derived key keep their values.
     - Good: almost every request ends inside grace, so the sweep carries only stragglers.
     - Bad: two committees work at once during grace, each on its own requests, and the departing seats stay online through grace.
     - Bad: TEE releases add one board commit from ROTATE to CLOSE.
     - Neutral: an envelope that binds an epoch after its sweep is refused at the public check. Its owner built it about two days before it was ordered.
   - Confirmation: conformance, Lean oracle `formal/lean-split/handoff`: `ho059_one_owner`, `ho036_owner_switch` and `ho044_carried_slot_board_state`; outcome, the spec-only Quint model of the next lane: one owning epoch per live request at every position, and no slot with two tickets.
   - Revisit when: the publicly verifiable reshare of O5 makes a carry cheap enough to switch every request at the activation, or the grace period changes.

81. **Every epoch ends in a handoff: 7 days, at most `⌊f/2⌋` seats scheduled and `f` in an emergency.** Lead pick, for owner confirmation.
   - Context and problem: DESIGN §8 gave no cadence and no number of seats per rotation. Fenrir nodes switch out a few at a time. A seat that fails during a rotation counts against `f` or `f'`, and the reshare needs `t = n − f` honest source dealers.
   - Drivers: the owner request of 2026-11-16 (keys shift to new keychains every so often), the item 42 lead pick (clocks in Midnight blocks), C5, C14, O5, HO-005, HO-006, HO-012, HO-023, HO-055.
   - Considered options:
     - (a) One handoff per epoch of 7 days (`Δ_rot = 5` days plus `Δ_grace = 2` days after the activation), which is a refresh when no seat changes. Every clock counts Midnight blocks: a day is the number of Midnight blocks in a day. A scheduled rotation replaces at most `⌊f/2⌋` seats, an emergency rotation at most `f`. Carries take at most `β = 10 %` of board bytes per block.
     - (b) Rotate only when the roster changes. Rejected: shares of one sharing would accumulate exposure for months, and a stolen share would stay useful.
     - (c) Enroll a joining seat at a new index of the same polynomial by share repair. Not chosen: it costs about `t` scalars per secret in place of a full reshare, but every departed seat's share stays a valid point of the live sharing.
     - (d) Allow up to `f` seats in a scheduled rotation. Rejected: it leaves no fault budget for a joining or departing seat that fails during the rotation.
   - Outcome: (a). `HANDOFF.md` §3.3 and §7.5; DESIGN §2.3 and §8.1. The grace period becomes 2 days of Midnight blocks after the activation in place of "1 epoch boundary + 2 days". Lead pick, for owner confirmation.
   - Consequences:
     - Good: every share of every standing secret gets a new polynomial each week, so shares stolen in two epochs do not combine.
     - Good: at most two epochs are live, which keeps the four-pool and two-`σ` bounds of DESIGN §7.4 and §11.6.
     - Good: a clock in Midnight blocks runs when the board stops, so a stalled committee cannot stop its own deadline.
     - Bad: the carry of the ECDSA inventory runs every week. At one million ECDSA addresses with 16 unused slots each it no longer fits in 5 days at `β = 10 %` (`HANDOFF.md` §9, O41).
     - Neutral: replacing three seats at `n = 9` takes three weekly rotations, or one emergency rotation of two seats and one scheduled rotation.
   - Confirmation: conformance, Lean oracle: the `too_many_seats` refusals and `ho055_two_epochs`; measurement, O41.
   - Revisit when: O41 measures the carry, or `n` grows past 17.

82. **What moves: standing secrets before the arming, `k_nf` unchanged, the backup at `E` kept, epoch keys and the seal group new.** Lead pick, for owner confirmation.
   - Context and problem: DESIGN §8 moved `x_f` and unused ECDSA slot shares and regenerated the seal-group secret. It said nothing about `k_nf`, the backup at `E` beyond a re-deal after every rotation, the seald Sessions of joining and departing seats, the seald committee descriptor, or the erase time of each old secret.
   - Drivers: C14, C15, C16, O5, O10, O32, DECISIONS 51, DESIGN §3.9, §7.4 and §7.8, HO-018, HO-022, HO-024, HO-045, HO-060 to HO-062.
   - Considered options:
     - (a) Carry `x_f` per curve and every unused ECDSA slot share in CARRY, before READY. Carry `k_nf` unchanged. Keep the backup at `E`, which holds constant terms that a handoff does not change. Regenerate epoch keys and the seal group, and discard free Schnorr slots. Scope the seald committee descriptor to the epoch. Erase every old share and key at grace end. Burn a carried slot copy when the board shows the slot used.
     - (b) Deal a new backup to `E` after every rotation, as §3.9 said. Rejected: it adds a step with `E` to every handoff and gains nothing, because the backed-up values do not change.
     - (c) Derive a new `k_nf` per epoch. Rejected: a carried ECDSA slot would get a second nullifier, and the seat-log check that no covered entry binds one nullifier to two tickets would miss the second binding.
     - (d) Erase old `x_f` shares at the activation. Rejected: until O5 closes, the epoch in grace is the only dealer source that can replace a committee that cannot sign.
   - Outcome: (a). `HANDOFF.md` §6 and findings A2, A7, A8 and A12; DESIGN §3.9, §7.8 and §8.3. Lead pick, for owner confirmation.
   - Consequences:
     - Good: every secret has one stated action, owner, time and erase rule.
     - Good: a handoff needs no step by `E`.
     - Bad: a non-TEE departed operator keeps `k_nf`, which links seat-log binding entries to slot ids it knows. It reveals no key.
     - Bad: seald needs an epoch-scoped committee descriptor, a change in Veritee outside this repository.
   - Confirmation: `HANDOFF.md` §6 lists every secret and authority; conformance, Lean oracle: `ho063_signable_preserved` (the ECDSA inventory follows the handoff).
   - Revisit when: `E` changes its membership rules, or seald takes a descriptor per epoch natively.

83. **One activation record, signed by the armed committee alone, switches the Midnight authority, and every committee signature is scoped to its epoch.** Lead pick, for owner confirmation.
   - Context and problem: DESIGN §7.5 wrote `EKS_e` as its own Midnight record with `q` boot-key signatures of Node Registry entries, and §7.9 and §7.10 used separate `replaceSlot` and `retire` writes. Nothing said when the contract stops accepting the old committee's checkpoints, and the carried VOID leaf, the birth certificate and the slot-root certificates were checked "against the epoch key set" with no epoch named. Operators could seat themselves through the Node Registry alone. The item 42 synthesis (`research/recovery-debate/SYNTHESIS.md`) asks that an honest handoff and a recovery be one operation, `activate`, with no step of the outgoing committee after the incoming one is armed.
   - Drivers: owner rule (Midnight writes batched, one root per checkpoint), owner rule (governance by rotated Fenrir operator keys), the item 42 lead pick (one `activate` operation), DECISIONS 52, C6, C11, AU-021, AU-022, CP-005, CP-006, HO-046 to HO-053, HO-065, HO-067.
   - Considered options:
     - (a) The activation record carries the checkpoint fields at the armed height `H`, `EKS_{e+1}`, the roster, the departing seats, the ROTATE with its governance signatures and the arm heartbeat under `X_f`, with `t'` signatures of the target epoch and none of the source epoch. The contract accepts it until the Midnight deadline `m_D`. After it lands the contract accepts only the new epoch's checkpoints. Every committee certificate names its epoch and is checked against that epoch's key set while the epoch is current or in grace. `authorize` checks no committee signature.
     - (b) A handover checkpoint signed by `q` seats of each epoch. Rejected: the outgoing committee could refuse its signatures after the incoming one is armed, which blocks the handoff and differs from a recovery.
     - (c) Separate `rotate`, `EKS`, `retire` and `replaceSlot` writes. Rejected: four kinds of write per handoff where one serves, against the batching rule.
     - (d) Check certificates against the current key set only. Rejected: a refill finished just before the activation and a reissue of a VOID leaf just after it would fail with no fault of the user.
   - Outcome: (a). `HANDOFF.md` §5 and findings A3 to A5, A9 and A10; DESIGN §7.5, §7.13, §8.4 and §11.6; HO-046 to HO-053, HO-065, HO-067; CP-006 reworded. Lead pick, for owner confirmation.
   - Consequences:
     - Good: a handoff adds no Midnight transaction. The activation record replaces one ordinary checkpoint and the per-epoch `EKS` write.
     - Good: no roster takes the committee authority without `q` governance signatures and `t'` live holders of `x_f`, and the outgoing committee cannot block the switch once the target is armed.
     - Bad: the board makes no block between `H` and the activation, about the Midnight inclusion time plus `F_M`.
     - Bad: Midnight verifies the edwards25519 heartbeat now, and the secp256k1 heartbeat only once Compact verifies secp256k1 (O43).
     - Neutral: a reissue after its leaf's grace end takes the root path.
   - Confirmation: conformance, Lean oracle: `ho032_authority_switch` and `ho_no_source_after_arm`; the contract test of O42.
   - Revisit when: item 42's `activate` lands, or Midnight adds a native key-rotation primitive for contracts.

84. **The target is armed by `n' − f'` READY posts and a heartbeat under `X_f`; Midnight decides activation or abort by a deadline.** Lead pick, for owner confirmation.
   - Context and problem: DESIGN §8.1 had READY from `n' − f'`, a deadline and an abort, with the old leader ordering HANDOVER. Under partial synchrony a late complaint can leave fewer than `t'` good holders after HANDOVER (O5). READY posts are claims: nothing showed that `t'` target seats could sign. The deadline counted board height, which stops when the committee stops.
   - Drivers: C13, C14, O5, O40, the item 42 lead pick (armed committee proved by a heartbeat, clocks in Midnight blocks), HO-008, HO-029 to HO-035, HO-064 to HO-067.
   - Considered options:
     - (a) After `n' − f'` READY posts for one qualified set and snapshot, a closed complaint window and no open restart, `t'` target seats sign an arm heartbeat under `X_f` per curve over a domain-separated message. The board block that commits it is `H`, and the source epoch casts no block vote above `H`. The activation record must land by the Midnight height `m_D`. Without it the rotation aborts and the source epoch resumes at `H + 1`. The epoch in grace keeps its shares, and a ROTATE with that epoch as its source replaces a committee of epoch `e + 1` that cannot sign.
     - (b) READY posts alone, with HANDOVER ordered by the old leader. Rejected: it shows claims, not `t'` live holders, and it leaves the last step to the outgoing committee.
     - (c) `q'` READY posts. Rejected: it leaves as few as `q' − f'` honest holders, fewer than `t'`.
     - (d) A deadline in board height. Rejected: a board that stops also stops its clock, and the two committees could read different outcomes.
   - Outcome: (a). `HANDOFF.md` §2.4, §2.6, §7.2 and §7.3; DESIGN §8.1; HO-029 to HO-035, HO-064 to HO-067. Lead pick, for owner confirmation.
   - Consequences:
     - Good: one committee has authority at every board position, Midnight settles the switch, and an abort loses nothing.
     - Good: the heartbeat shows `t'` live shares of `x_f` before the source stops voting.
     - Bad: the heartbeat is a signature under `X_f`. It is not a valid signature under any address key, because every address adds a user shard. Its message domain keeps it apart from every protocol message, and O6 covers it with the other committee signatures.
     - Bad: liveness of the arming still rests on the complaint window of O5, until the publicly verifiable reshare replaces it.
   - Confirmation: conformance, Lean oracle: `ho_completes` (under the O5 hypothesis), `ho_no_source_after_arm` and `ho035_abort_keeps_old`.
   - Revisit when: O5 closes with the publicly verifiable reshare, or item 42 fixes its own heartbeat format.

85. **A joining seat is continuous from the activation record.** Lead pick, for owner confirmation.
   - Context and problem: CP-009 refuses a checkpoint `cp2` that keeps the boot counters of fewer than `w + 1` seats unless it jumps the reservation window. A joining seat has no counter in the previous checkpoint, and a departing seat drops out, so an activation record could look like a whole-committee restart. That forces the jump: every pool burns its window, and the live requests on those slots end VOID for their owners to re-post.
   - Drivers: owner rule (owner online only to initiate and broadcast), C16, CP-009, CP-017, DECISIONS 69, HO-054.
   - Considered options:
     - (a) A joining seat is continuous from the activation record that names it, and CP-009 counts the continuing seats across that record. At most `f` seats change, so `n − f ≥ w + 1` seats stay continuous.
     - (b) Take the jump at every handoff. Rejected: it burns `B` indices per pool each epoch and voids the live requests on them.
     - (c) Exempt every activation record from CP-009. Rejected: a real whole-committee restart at the same time would pass unseen.
   - Outcome: (a). `HANDOFF.md` finding A6; DESIGN §7.13; HO-054. Lead pick, for owner confirmation.
   - Consequences:
     - Good: a handoff burns no slot and voids no request.
     - Neutral: the rule holds because entry 81 bounds the seats per rotation by `f`.
   - Confirmation: the contract test of O42; a spec-only Quint scenario of the next lane with one seat swapped and no jump.
   - Revisit when: a rotation may change more than `f` seats.

86. **A checkpoint needs `t` signers, not `q`.** Lead pick, for owner confirmation.
   - Context and problem: CP-003 and DESIGN §7.13 let `q` node signatures land a checkpoint. At launch `q = 6` and `t = 7`. Six seats could keep checkpoints landing, and so keep the recovery clock from firing, while no seven of them can sign. The item 42 synthesis names this as a broken dead-man clock. The same count matters for the activation record, which must show a committee that can sign.
   - Drivers: C15, C16, the item 42 lead pick, CP-003, HO-047, HO-050, HO-068.
   - Considered options:
     - (a) Every checkpoint, the activation record included, needs `t` valid signatures of its epoch's key set.
     - (b) Keep `q` and add a heartbeat under `X_f` to each checkpoint. Not chosen here: item 42 owns the heartbeat of ordinary checkpoints, and `t` signers close the gap without a new signature.
     - (c) Keep `q`. Rejected: it lets a committee that cannot sign look live.
   - Outcome: (a). DESIGN §7.13 and §11.6; CP-003; HO-050 and HO-068. Board certificates (birth, acknowledgement, slot roots, VOID leaves) keep `q`, because they attest board facts, not the ability to sign. Lead pick, for owner confirmation.
   - Consequences:
     - Good: a landed checkpoint shows `t` seats alive, the number that can sign.
     - Bad: at `n = 9` a checkpoint needs 7 of 9 seats, so 3 silent seats stop checkpoints where 4 did before. At `n = 17`, `q = t = 12` and nothing changes.
     - Neutral: the checkpoint grows by one signature at `n = 9`, 64 B.
   - Confirmation: conformance, Lean oracle: the `too_few_signers` refusal; the contract test of O42.
   - Revisit when: item 42 settles its dead-man trigger.
