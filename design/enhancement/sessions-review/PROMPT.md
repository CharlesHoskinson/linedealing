You are an independent reviewer of a change to a confidential-computing key service. Review it adversarially, as a protocol engineer and cryptographer who wants to find what is wrong. Do not edit any file in the bundle. Do not run git.

The service is `seald`, a daemon inside each confidential VM of an `n`-node signing committee. Today its committee secrets (PRF shares, key shares, nonce-slot shares, presignature shares, in-flight request state) live in RAM only. The change adds "sessions": versioned records of that state, sealed under a key that `t` peer enclaves derive with a threshold PRF, written to local disk, replicated to the peers and fenced by a peer witness log.

The bundle (BUNDLE_DIR):
- BUNDLE_DIR/change/proposal.md, BUNDLE_DIR/change/design.md: the change and its reasons. Read both in full.
- BUNDLE_DIR/change/specs/seald-sessions/spec.md: the requirements, EARS form, IDs SS-001 to SS-101, each with scenarios. Read in full. This is the normative text.
- BUNDLE_DIR/docs/committee-signing-mode.md and BUNDLE_DIR/docs/committee-mode.md: the current committee mode (boot tickets, evidence classes, tier 0 / tier 1 storage, peer witness, recovery group). Read the parts the change cites.
- BUNDLE_DIR/seald/src/*.rs: the current `seald` code. `witness.rs`, `peer.rs`, `group.rs`, `store.rs`, `fence.rs` and `recovery.rs` are the most relevant. Read what you need to check a claim about the current behavior.
- BUNDLE_DIR/split-line/DESIGN.md: the signing protocol the committee runs. The change cites §4.1 (nonce slots), §7.4 (tier 0, `K_tpm`, PRF share), §7.7 (peer witness, `slot` entries, `anchor_before_release`) and §7.11 (recovery group, burn rule). Read those sections.

Parameters: `t = n − f`, `w = n − 1 − f` witness acks, collusion bound `c ≤ n − 1 − 2f` for the peer witness. Launch profile `n = 9`, `f = 2`.

The four items under "Decisions" in design.md are fixed choices. You may argue against them; give the argument and the scenario, and mark the finding "decision challenge".

Required checks. For each item, either give a concrete failure scenario or state why it holds, with the requirement IDs that make it hold:
1. G1 to G5 of design.md, one by one.
2. The witness fence: no PRF partial for a version below the highest witnessed version; a restored old record or a stale peer replica does not open. Consider forgetful peers (wiped tier 0, rolled-back disks), clones and superseded boot tickets, and peers that join the quorum after missing versions.
3. Nonce-slot binding under `c ≤ n − 1 − 2f`: one nonce slot never releases partials for two different ticket digests. Check `slot_bind`, `slot_release_ok`, the `unsealed` set, a crash between the two witness rounds, and the case where a restored session shows a slot `free` that was bound.
4. The reservation window and the whole-committee restart burn: the decision rule (`c < w + 1` continuous seats, from the ledger only), the burn sets `(h_cp, h_cp + B]` and `cp.pending`, the lower bound `slot_stale`, the contract rule for the checkpoint after a restart, a node that boots late, nodes that disagree on `cp_boot`, and a checkpoint posted during the restart.
5. Whole-committee restart from rolled-back disks, including every disk rolled back to the same old state, and a mix of rolled-back and current disks.
6. Replication: a replacement VM with a blank disk, the majority-digest rule and the `conflict` tie rule, two records for one version, a peer that acks and then loses its replica, the 16 MiB tier-0 limit.
7. Epochs: `rekey`, `close_epoch`, `epoch_in_use`, a crash during a rekey, and a session that no peer has witnessed in the new epoch.
8. Spec and design consistency: every statement in design.md that the spec contradicts or omits, every requirement that conflicts with another, refusal orders (SS-090, SS-091) that disagree with the requirements, error codes used but not listed, and states with no defined behavior.
9. Consistency with the current code and docs: any requirement that relies on a property the current `seald` or the docs do not have, and the change does not add.

Report format (Markdown). For every finding:
- ID (F1, F2, ...)
- Severity: blocking (breaks G1 to G5 or a safety claim, or makes the spec unimplementable as written), major (a real gap that needs a fix or an honest change of a claim), minor (clarity, inconsistency without safety impact)
- Location: file and section, and the requirement IDs
- Claim affected: G1 to G5, the witness fence, slot binding, window burn, restart, replication, epochs, or the requirement
- Failure scenario: a concrete sequence of steps (which nodes, which versions, which slot indices, which checkpoint values) that produces the failure
- Fix: the smallest change that closes it, as requirement text where you can

Then a list of the required checks above that you found sound, each with one line of reason. Do not pad: no finding without a concrete scenario. Write everything in English. Write the full report to OUT_FILE and also return it as your final message.
